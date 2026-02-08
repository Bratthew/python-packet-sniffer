import socket
import struct
import textwrap
import threading
import tkinter as tk
from tkinter import scrolledtext
from tkinter import messagebox
import time
import requests
import ids_rules
import sqlite3
import subprocess
import matplotlib.pyplot as plt

ip_geo_cache = {}

PCAP_GLOBAL_HEADER_FMT = '@ I H H i I I I'
PCAP_PACKET_HEADER_FMT = '@ I I I I'
LINKTYPE_ETHERNET = 1

stop_sniffing = False
is_recording = False
pcap_filename = "capture.pcap"

def block_ip(ip_address):
	if ip_address == "127.0.0.1" or ip_address.startswith("10.0.2"):
		print(f"[!] Safety: Ignoring block request for local IP {ip_address}")
		return

	try:
		command = ["iptables", "-A", "INPUT", "-s", ip_address, "-j", "DROP"]

		subprocess.run(command, check=True)
		print(f"[+] Firewall: Successfully blocked {ip_address}")
		return True
	except Exception as e:
		print(f"[-] Firewall Error: {e}")
		return False

def get_tls_sni(payload):
	try:
		if payload[0] != 0x16 or payload[1] != 0x03:
			return None

		if payload[5] != 0x01:
			return None

		cursor = 43
		
		session_id_len = payload[cursor]
		cursor += 1 + session_id_len

		cipher_suites_len = struct.unpack('!H', payload[cursor:cursor+2])[0]
		cursor += 2 + cipher_suites_len

		comp_methods_len = payload[cursor]
		cursor += 1 + comp_methods_len

		ext_len = struct.unpack('!H', payload[cursor:cursor+2])[0]
		cursor += 2

		end_of_extensions = cursor + ext_len

		while cursor < end_of_extensions:
			ext_type = struct.unpack('!H', payload[cursor:cursor+2])[0]
			ext_data_len = struct.unpack('!H', payload[cursor+2:cursor+4])[0]

			if ext_type == 0x00:
				name_len = struct.unpack('!H', payload[cursor+7:cursor+9])[0]
				server_name = payload[cursor+9 : cursor+9+name_len]
				return server_name.decode('utf-8')

			cursor += 4 + ext_data_len

	except Exception as e:
		return None
		
	return None

def create_pcap_file(filename="capture.pcap"):

	with open(filename, 'wb') as f:
		header = struct.pack(
			PCAP_GLOBAL_HEADER_FMT,
			0xa1b2c3d4, 2, 4, 0, 0, 65535, LINKTYPE_ETHERNET
		)
		f.write(header)

def append_to_pcap(filename, raw_data):
	with open(filename, 'ab') as f:
		ts = time.time()
		ts_sec = int(ts)
		ts_usec = int((ts - ts_sec) * 1_000_000)
		length = len(raw_data)

		pkt_header = struct.pack(
			PCAP_PACKET_HEADER_FMT,
			ts_sec, ts_usec, length, length
		)
		
		f.write(pkt_header)
		f.write(raw_data)

def init_db():
	conn = sqlite3.connect('sniffer_logs.db')
	c = conn.cursor()
	c.execute('''CREATE TABLE IF NOT EXISTS alerts
		     (id INTEGER PRIMARY KEY AUTOINCREMENT,
		      timestamp TEXT,
		      src_ip TEXT,
		      attack_name TEXT,
		      description TEXT)''')
	conn.commit()
	conn.close()

def log_alert_to_db(timestamp, src_ip, attack_name, description):
	try:
		conn = sqlite3.connect('sniffer_logs.db')
		c = conn.cursor()
		c.execute("INSERT INTO alerts (timestamp, src_ip, attack_name, description) VALUES (?, ?, ?, ?)", (timestamp, src_ip, attack_name, description))
		conn.commit()
		conn.close()
		print(f"[DB] Saved alert: {attack_name}")
	except Exception as e:
		print(f"[DB Error] {e}")

def get_geolocation(ip_addr):
	if ip_addr in ip_geo_cache:
		return ip_geo_cache[ip_addr]

	if ip_addr.startswith("192.168.") or ip_addr.startswith("10.") or ip_addr.startswith("172."):
		ip_geo_cache[ip_addr] = "Local"
		return "Local"

	try:
		response = requests.get(f"http://ip-api.com/json/{ip_addr}", timeout=2)
		data = response.json()

		if data['status'] == 'success':
			country = data['country']
			city = data['city']
			location = f"{city}, {country}"
			ip_geo_cache[ip_addr] = location
			return location
		else:
			ip_geo_cache[ip_addr] = "Unknown"
			return "Unknown"

	except:
		return "Error"

def show_stats():
	conn = sqlite3.connect('sniffer_logs.db')
	c = conn.cursor()

	c.execute("SELECT attack_name, COUNT(*) FROM alerts GROUP BY attack_name")
	data = c.fetchall()
	conn.close()

	if not data:
		messagebox.showinfo("Info", "No data to analyze yet!")
		return

	labels = [row[0] for row in data]
	counts = [row[1] for row in data]

	plt.figure(figsize=(7, 7))
	plt.pie(counts, labels=labels, autopct='%1.1f%%')
	plt.title("Intrustion Attempt Distribution")
	plt.show()

def start_sniffer_thread(log_widget):
	global stop_sniffing
	stop_sniffing = False

	try:
		conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
	except PermissionError:
		messagebox.showerror("Error", "Must be ran as ROOT(sudo)")
		return

	log_widget.insert(tk.END, "[*] Sniffer began")
	
	while not stop_sniffing:
		try:
			conn.settimeout(1)
			raw_data, addr = conn.recvfrom(65535)

			dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)

			if eth_proto == 8:
				(version, header_length, ttl, proto, src, target, data) = ipv4_packet(data)

			#	if src == "127.0.0.1": continue

				timestamp = time.strftime("%H:%M:%S")
				log_msg = f"[{timestamp}] {src} -> {target}"

				if proto == 6:
					src_port, dest_port, seq, ack, urg, ack_flag, psh, rst, syn, fin, payload = tcp_segment(data)
					current_msg = ""
					if len(payload) > 0:
						attack_name, attack_desc = ids_rules.check_signatures(payload)
						if attack_name:
							alert_msg = f"[!!!] ALERT [{timestamp}]: {attack_name} from {src}\n	Description: {attack_desc}\n"
							alert_area.insert(tk.END, alert_msg)
							alert_area.see(tk.END)
							log_alert_to_db(timestamp, src, attack_name, attack_desc)
							if auto_block_var.get():
								block_ip(src)
								alert_msg += f"		[ACTION]: FIREWALL BLOCKED {src}!\n"
								alert_area.insert(tk.END, f"	[ACTION]: FIREWALL BLOCKED {src}!\n")

							current_msg += f" | [THREAT DETECTED: {attack_name}]"

					sni = get_tls_sni(payload)
					if sni:
						log_msg += f" | [HTTPS] Handshake: {sni}\n"
						log_widget.insert(tk.END, log_msg)
						log_widget.see(tk.END)

						if is_recording: append_to_pcap(pcap_filename, raw_data)
						continue

					if len(payload) > 0:
						try:

							decoded = payload.decode('utf-8')
							if "GET" in decoded or "POST" in decoded or "HTTP" in decoded:
								first_line = decoded.split('\n')[0]
								log_msg += f" | [HTTP] {first_line}\n"
								log_widget.insert(tk.END, log_msg)
								log_widget.see(tk.END)

								if is_recording:
									append_to_pcap(pcap_filename, raw_data)
								continue
						except:
							pass


					if len(payload) > 50:
						log_msg += f" | [Data] {len(payload)} bytes\n"
		except socket.timeout:
			continue
		except Exception as e:
			print(f"Error: {e}")
			break

	conn.close()
	log_widget.insert(tk.END, "[*] Sniffer stopped.")

def ethernet_frame(data):
	dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
	return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:]

def get_mac_addr(bytes_addr):
	bytes_str = map('{:02x}'.format, bytes_addr)
	return ':'.join(bytes_str).upper()

def ipv4_packet(data):
	version_header_length = data[0]
	version = version_header_length >> 4
	header_length = (version_header_length & 15) * 4

	ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
	return version, header_length, ttl, proto, ipv4(src), ipv4(target), data[header_length:]

def ipv4(addr):
	return '.'.join(map(str, addr))

def tcp_segment(data):
	(src_port, dest_port, sequence, acknowledgement, offset_reserved_flags) = struct.unpack('! H H L L H', data[:14])

	offset = (offset_reserved_flags >> 12) * 4
	flag_urg = (offset_reserved_flags & 32) >> 5
	flag_ack = (offset_reserved_flags & 16) >> 4
	flag_psh = (offset_reserved_flags & 8) >> 3
	flag_rst = (offset_reserved_flags & 4) >> 2
	flag_syn = (offset_reserved_flags & 2) >> 1
	flag_fin = offset_reserved_flags & 1

	return src_port, dest_port, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:]

def toggle_recording():
	global is_recording
	if not is_recording:
		is_recording = True
		create_pcap_file(pcap_filename)
		btn_record.config(text="Stop Recording", bg="orange")
		log_area.insert(tk.END, f"[*] Recording started. Saving to {pcap_filename}..\n")
	else:
		is_recording = False
		btn_record.config(text="Record to PCAP", bg="blue")
		log_area.insert(tk.END, f"[*] Recording saved to {pcap_filename}\n")

def on_start():
	t = threading.Thread(target=start_sniffer_thread, args=(log_area,))
	t.daemon = True
	t.start()

def on_stop():
	global stop_sniffing
	stop_sniffing = True

def show_history():
	history_win = tk.Toplevel(root)
	history_win.title("Alert History (Database)")
	history_win.geometry("600x400")

	hist_text = scrolledtext.ScrolledText(history_win, width=70, height=20)
	hist_text.pack(pady=10, padx=10)

	try:
		conn = sqlite3.connect('sniffer_logs.db')
		c = conn.cursor()
		c.execute("SELECT * FROM alerts ORDER BY id DESC")
		rows = c.fetchall()
		conn.close()

		if not rows:
			hist_text.insert(tk.END, "No alerts found in database")
		else:
			for row in rows:
				hist_text.insert(tk.END, f"[{row[1]}] {row[3]} from {row[2]}\nDesc: {row[4]}\n" + "-"*40 + "\n")

	except Exception as e:
		hist_text.insert(tk.END, f"Error loading DB: {e}")

root = tk.Tk()
root.title("Python Packet Sniffer")
root.geometry("600x500")

frame = tk.Frame(root)
frame.pack(pady=10)

auto_block_var = tk.BooleanVar()

chk_block = tk.Checkbutton(frame, text="Auto-Block Threats", variable=auto_block_var, fg="red")
chk_block.pack(side=tk.LEFT, padx=10)

btn_start = tk.Button(frame, text="Start Sniffing", command=on_start, bg="green", fg="white")
btn_start.pack(side=tk.LEFT, padx=10)

btn_stop = tk.Button(frame, text="Stop Sniffing", command=on_stop, bg="red", fg="white")
btn_stop.pack(side=tk.LEFT, padx=10)
btn_record = tk.Button(frame, text="Record to PCAP",
command = toggle_recording, bg="blue", fg="white")
btn_record.pack(side=tk.LEFT, padx=10)

btn_history = tk.Button(frame, text="View Logs", command=show_history, bg="purple", fg="white")
btn_history.pack(side=tk.LEFT, padx=10)

btn_stats = tk.Button(frame, text="Stats Graph", command=show_stats, bg="orange")
btn_stats.pack(side=tk.LEFT, padx=10)

lbl_filter = tk.Label(frame, text="Filter IP:")
lbl_filter.pack(side=tk.LEFT, padx=5)

entry_filter = tk.Entry(frame, width=15)
entry_filter.pack(side=tk.LEFT, padx=5)

log_area = scrolledtext.ScrolledText(root, width=70, height=15)
log_area.pack(pady=10)

lbl_alerts = tk.Label(root, text="[ IDS ALERTS ]", fg="red", font=("Arial", 10, "bold"))
lbl_alerts.pack(pady=5)

alert_area = scrolledtext.ScrolledText(root, width=70, height=8,fg="red")
alert_area.pack(pady=5)

init_db()

root.mainloop()
