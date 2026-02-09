import socket
import struct
import threading
import time
import requests
import sqlite3
import subprocess
import os
import customtkinter as ctk
from tkinter import messagebox
import matplotlib.pyplot as plt
import ids_rules
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter

ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

ip_geo_cache = {}
stop_sniffing = False
is_recording = False
pcap_filename = "capture.pcap"

PCAP_GLOBAL_HEADER_FMT = '@ I H H i I I I'
PCAP_PACKET_HEADER_FMT = '@ I I I I'
LINKTYPE_ETHERNET = 1

def block_ip(ip_address):
	if ip_address == "127.0.0.1" or ip_address.startswith("10.0.2"):
		return False
	try:
		command = ["iptables", "-A", "INPUT", "-s", ip_address, "-j", "DROP"]
		subprocess.run(command, check = True)
		return True
	except Exception:
		return False

def start_honeyport(port, log_widget):
	try:
		server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		server.bind(("0.0.0.0", port))
		server.listen(5)
		log_widget.insert("end", f"[*] HONEYPOT TRAP Active on Port {port}..\n")
		while True:
			client, addr = server.accept()
			attacker_ip = addr[0]
			alert_msg = f"[!!!] HONEYPOT TRIGGERED by {attacker_ip}!\n"
			log_widget.insert("end", alert_msg)
			data = "No Data"
			try:
				client.send(b"SSH-2.0-OpenSSH_Legacy_v4.3\nPassword: ")
				client.settimeout(3)
				data = client.recv(1024).decode('utf-8').strip()
				log_widget.insert("end", f"	[INTEL] Attacker tried: {data}\n")
			except:
				pass
			client.close()
			if block_ip(attacker_ip):
				log_widget.insert("end", f"	[COUNTERMEASURE] Banned {attacker_ip}\n")
			log_alert_to_db(time.strftime("%H:%M:%S"), attacker_ip, "Honeypot Trigger", f"Port {port} | Input: {data}")
	except Exception as e:
		log_widget.insert("end", f"[-] Honeypot Error: {e}\n")

def get_tls_sni(payload):
	try:
		if len(payload) < 43: return None
		if payload[0] != 0x16 or payload[1] != 0x03: return None
		if payload[5] != 0x01: return None
		cursor = 43
		if cursor >= len(payload): return None

		session_id_len = payload[cursor]
		cursor += 1 + session_id_len
		if cursor + 2 >= len(payload): return None
		cipher_suites_len = struct.unpack('!H', payload[cursor:cursor+2])[0]

		cursor += 2 + cipher_suites_len
		if cursor >= len(payload): return None

		comp_methods_len = payload[cursor]
		cursor += 1 + comp_methods_len
		if cursor + 2 >= len(payload): return None

		ext_len = struct.unpack('!H', payload[cursor:cursor+2])[0]
		cursor += 2
		end_of_extensions = cursor + ext_len
		if end_of_extension > len(payload): return None

		while cursor < end_of_extensions:
			if cursor + 4 > len(payload): break

			ext_type = struct.unpack('!H', payload[cursor:cursor+2])[0]
			ext_data_len = struct.unpack('!H', payload[cursor+2:cursor+4])[0]

			if ext_type == 0x00:
				if cursor + 9 > len(payload): break

				name_len = struct.unpack('!H', payload[cursor+7:cursor+9])[0]
				name_start = cursor + 9
				name_end = name_start + name_len

				if name_end > len(payload): break

				server_name = payload[name_start : name_end]
				return server_name.decode('utf-8')
			cursor += 4 + ext_data_len
	except:
		return None
	return None

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

	return src_port, dest_port, sequence, acknowledgement, 0, 0, 0, 0, 0, 0, data[offset:]

def udp_segment(data):
	src_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])

	return src_port, dest_port, size, data[8:]

def icmp_packet(data):
	icmp_type, code, checksum = struct.unpack('! B B H', data[:4])

	return icmp_type, code, checksum, data[4:]

def create_pcap_file(filename="capture.pcap"):
	with open(filename, 'wb') as f:
		header = struct.pack(PCAP_GLOBAL_HEADER_FMT, 0xa1b2c3d4, 2, 4, 0, 0, 65535, LINKTYPE_ETHERNET)
		f.write(header)

def append_to_pcap(filename, raw_data):
	with open(filename, 'ab') as f:
		ts = time.time()
		ts_sec = int(ts)
		ts_usec = int((ts - ts_sec) * 1_000_000)
		length = len(raw_data)
		pkt_header = struct.pack(PCAP_PACKET_HEADER_FMT, ts_sec, ts_usec, length, length)
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
	except:
		pass

def get_geolocation(ip_addr):
	if ip_addr in ip_geo_cache:
		return ip_geo_cache[ip_addr]

	if ip_addr.startswith("192.168.") or ip_addr.startswith("10."):
		ip_geo_cache[ip_addr] = "Local"
		return "Local"

	if ip_addr.startswith("172."):
		second = int(ip_addr.split('.')[1])
		if 16 <= second <= 31:
			ip_geo_cache[ip_addr] = "Local"
			return "Local"

	try:
		response = requests.get(f"http://ip-api.com/json/{ip_addr}", timeout=1)
		data = response.json()
		if data['status'] == 'success':
			loc = f"{data['city']}, {data['country']}"
			ip_geo_cache[ip_addr] = loc
			return loc
	except:
		pass
	ip_geo_cache[ip_addr] = "Unknown"
	return "Unknown"

def detect_os(ttl):
	if 0 <= ttl <= 64:
		return "Linux/Unix"

	elif 65 <= ttl <= 128: 
		return "Windows"

	elif 129 <= ttl <= 255: 
		return "Cisco/Solaris"

	return "Unknown"

def show_stats():
	conn = sqlite3.connect('sniffer_logs.db')
	c = conn.cursor()
	c.execute("SELECT attack_name, COUNT(*) FROM alerts GROUP BY attack_name")
	data = c.fetchall()
	conn.close()
	if not data:
		messagebox.showinfo("Info", "No data to analyze")
		return

	labels = [row[0] for row in data]
	counts = [row[1] for row in data]
	plt.style.use('dark_background')
	plt.figure(figsize=(6, 6))
	plt.pie(counts, labels=labels, autopct='%1.1f%%')
	plt.title("Intrusion Attempt Distribution")
	plt.show()

def export_pdf():
	filename = "Security_Report.pdf"

	try:
		c = canvas.Canvas(filename, pagesize=letter)
		width, height = letter
		c.setFont("Helvetica-Bold", 20)
		c.drawString(50, height - 50, "Network Intrusion Report")
		c.setFont("Helvetica", 12)
		c.drawString(50, height - 70, f"Generated: {time.ctime()}")
		conn = sqlite3.connect('sniffer_logs.db')
		cursor = conn.cursor()
		c.setFont("Helvetica-Bold", 14)
		c.drawString(50, height - 130, "TOp Attacking IPs:")
		cursor.execute("SELECT src_ip, COUNT(*) FROM alerts GROUP BY src_ip ORDER BY COUNT(*) DESC LIMIT 5")
		top_ips = cursor.fetchall()
		y = height - 150
		c.setFont("Helvetica", 12)
		for ip, count in top_ips:
			c.drawString(70, y, f"IP: {ip} - {count} Alerts")
			y -= 20

		c.save()
		conn.close()
		messagebox.showinfo("Success", f"PDF saved as {filename}")
	except Exception as e:
		messagebox.showerror("Error", str(e))

def show_history():
	hist_win = ctk.CTkToplevel(app)
	hist_win.title("Database Logs")
	hist_win.geometry("600x400")
	txt = ctk.CTkTextbox(hist_win, width=580, height=380, font=("Consolas", 12))
	txt.pack(pady=10, padx=10)
	try:
		conn = sqlite3.connect('sniffer_logs.db')
		c = conn.cursor()
		c.execute("SELECT * FROM alerts ORDER BY id DESC")
		rows = c.fetchall()
		conn.close()
		if not rows: txt.insert("0.0", "NO alerts found")
		else:
			for row in rows:
				txt.insert("end", f"[{row[1]}] {row[3]} from {row[2]}\nDesc: {row[4]}\n" + "-"*40 + "\n")
	except:
		pass

def toggle_recording():
	global is_recording
	if not is_recording:
		is_recording = True
		create_pcap_file(pcap_filename)
		btn_record.configure(text="Stop Recording", fg_color="orange")
		log_box.insert("end", f"[*] Recording started; Saving to {pcap_filename}..\n")
	else:
		is_recording = False
		btn_record.configure(text="Record PCAP", fg_color="#3B8ED0")
		log_box.insert("end", f"[*] Recording saved to {pcap_filename}\n")

def toggle_honeyport():
	if chk_honey_var.get():
		t = threading.Thread(target = start_honeyport, args=(9999, log_box))
		t.daemon = True
		t.start()
	else:
		messagebox.showinfo("Info", "Honeypot running. Restart app to stop.")

def start_sniffer_thread():
	global stop_sniffing
	stop_sniffing = False
	last_log_entry = ""
	packet_counts = {}
	last_time_check = time.time()
	THRESHOLD_PPS = 50

	try:
		conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
	except PermissionError:
		messagebox.showerror("Error", "Must be ran as ROOT (sudo)")
		return

	log_box.insert("end", "[*] Sniffer running\n")
	while not stop_sniffing:
		try:
			conn.settimeout(1)
			raw_data, addr = conn.recvfrom(65535)
			dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)

			if eth_proto == 8:
				(version, header_length, ttl, proto, src, target, data) = ipv4_packet(data)
				packet_counts[src] = packet_counts.get(src, 0) + 1

				if time.time() - last_time_check > 2:
					for ip, count in packet_counts.items():
						if count > THRESHOLD_PPS:
							attack_name = "Potential DoS / Flood"
							attack_desc = f"High Traffic Volume: {count} packets in 2s"
							alert_msg = f"[!!!] ANOMALY [{timestamp}]: {attack_name} from {ip}\n"
							alert_box.insert("end", alert_msg)
							alert_box.see("end")
							log_alert_to_db(timestamp, ip, attack_name, attack_desc)

							if chk_block_var.get():
								if block_ip(ip):
									alert_box.insert("end", f"[ACTION]: FIREWALL BLOCKED {ip}!\n")

						packet_counts = {}
						last_time_check = time.time()

				filter_txt = entry_filter.get().strip()

				if filter_txt and (filter_txt not in src and filter_txt not in target):
					continue
				timestamp = time.strftime("%H:%M:%S")
				src_os = detect_os(ttl)
				log_msg = f"[{timestamp}] {src} ({src_os}) -> {target}"

				if proto == 6:
					src_port, dest_port, seq, ack, urg, ack_flag, psh, rst, syn, fin, payload = tcp_segment(data)

					if len(payload) > 0:
						attack_name, attack_desc = ids_rules.check_signatures(payload)

						if attack_name:
							alert_msg = f"[!!!] ALERT [{timestamp}]: {attack_name} from {src}\n"
							alert_box.insert("end", alert_msg)
							alert_box.see("end")
							log_alert_to_db(timestamp, src, attack_name, attack_desc)

							if chk_block_var.get():
								if block_ip(src):
									alert_box.insert("end", f" [ACTION]: FIREWALL BLOCKED {src}!\n")
									log_msg += " [BLOCKED]"
								log_msg += f" | [THREAT: {attack_name}]"
							sni = get_tls_sni(payload)

							if sni:
								log_msg += f" | [HTTPS] Handshake: {sni}"
							elif len(payload) > 0:
								try:
									decoded = payload.decode('utf-8')
									if "GET" in decoded or "POST" in decoded or "HTTP" in decoded:
										first_line = decoded.split('\n')[0]
										log_msg == f" | [HTTP] {first_line}"
								except:
									pass
							if not src.startswith("10.") and not src.startswith("192."):
								loc = get_geolocation(src)
								if loc != "Unknown": log_msg += f" [Src: {loc}]"
							elif not target.startswith("10.") and not target.startswith("192."):
								loc = get_geolocation(target)
								if loc != "Unknown": log_msg += f" [Dst: {loc}]"
						elif proto == 17:
							src_port, dest_port, size, payload = udp_segment(data)
							log_msg += f" | Protocol: UDP ({src_port} -> {dest_port})"

							if len(payload) > 0:
								attack_name, attack_desc = ids_rules.check_signatures(payload)
								if attack_name:
									alert_msg = f"[!!!] ALERT [{timestamp}]: {attack_name} from {src}\n"
									alert_box.insert("end", alert_msg)
									log_alert_to_db(timestamp, src, attack_name, attack_desc)

									if chk_block_var.get(): block_ip(src)
									log_msg += f" | [THREAT: {attack_name}]"
							if src_port == 53 or dest_port == 53:
								log_msg += " | [DNS] Query/Response"
						elif proto == 1:
							icmp_type, code, checksum, payload = icmp_packet(data)
							if icmp_type == 8: log_msg += " | [ICMP] Ping Requests"
							elif icmp_type == 0: log_msg += " | [ICMP] Ping Reply"
							else: log_msg += f" | [ICMP] Type {icmp_type}"
						if log_msg != last_log_entry or "THREAT" in log_msg:
							log_box.insert("end", log_msg + "\n")
							log_box.see("end")
							last_log_entry = log_msg
							if is_recording: append_to_pcap(pcap_filename, raw_data)
		except socket.timeout:
			continue
		except Exception as e:
			print(f"Error: {e}")
			continue

	conn.close()
	log_box.insert("end", "[*] Sniffer stopped\n")

def on_start():
	t = threading.Thread(target=start_sniffer_thread)
	t.daemon = True
	t.start()
	btn_start.configure(state="disabled", fg_color="gray")
	btn_stop.configure(state="normal", fg_color="#C0392B")

def on_stop():
	global stop_sniffing
	stop_sniffing = True
	btn_start.configure(state="normal", fg_color="#2CC985")
	btn_stop.configure(state="disabled", fg_color="gray")

app = ctk.CTk()
app.title("NIPS - Network Intrusion Prevention System")
app.geometry("900x700")

sidebar = ctk.CTkFrame(app, width=200, corner_radius=0)
sidebar.pack(side="left", fill="y", padx=0, pady=0)

lbl_title = ctk.CTkLabel(sidebar, text="SECURE\nMONITOR", font=("Roboto", 20, "bold"))
lbl_title.pack(pady=20)

btn_start = ctk.CTkButton(sidebar, text="START MONITOR", command=on_start, fg_color="#2CC985", hover_color="#229966")
btn_start.pack(pady=10, padx=10)

btn_stop = ctk.CTkButton(sidebar, text="STOP MONITOR", command=on_stop, fg_color="#C0392B", hover_color="#962D22", state="disabled")
btn_stop.pack(pady=10, padx=10)

ctk.CTkLabel(sidebar, text="Tools:", font=("Roboto", 12)).pack(pady=(20,5))
btn_record = ctk.CTkButton(sidebar, text="Record PCAP", command=toggle_recording)
btn_record.pack(pady=5, padx=10)
btn_history = ctk.CTkButton(sidebar, text="View DB Logs", command=show_history, fg_color="#5B2C6F", hover_color="#4A235A")
btn_history.pack(pady=5, padx=10)
btn_stats = ctk.CTkButton(sidebar, text="View Stats", command=show_stats, fg_color="#D35400", hover_color="#A04000")
btn_stats.pack(pady=5, padx=10)
btn_pdf = ctk.CTkButton(sidebar, text="Export PDF", command=export_pdf, fg_color="#1F618D", hover_color="#154360")
btn_pdf.pack(pady=5, padx=10)

ctk.CTkLabel(sidebar, text="Defenses:", font=("Roboto", 12)).pack(pady=(20,5))
entry_filter = ctk.CTkEntry(sidebar, placeholder_text="Filter IP...")
entry_filter.pack(pady=5, padx=10)

chk_block_var = ctk.BooleanVar()
chk_block = ctk.CTkCheckBox(sidebar, text="Auto-Block", variable=chk_block_var, text_color="#FF5555", hover_color="#FF5555")
chk_block.pack(pady=10)

chk_honey_var = ctk.BooleanVar()
chk_honey = ctk.CTkSwitch(sidebar, text="Activate Trap", command=toggle_honeyport, variable=chk_honey_var, progress_color="#D35400")
chk_honey.pack(pady=10)

main_frame = ctk.CTkFrame(app, corner_radius=10)
main_frame.pack(side="right", fill="both", expand=True, padx=10, pady=10)

lbl_live = ctk.CTkLabel(main_frame, text="LIVE TRAFFIC LOG", font=("Roboto", 14, "bold"))
lbl_live.pack(pady=5, anchor="w", padx=10)
log_box = ctk.CTkTextbox(main_frame, width=600, height=350, font=("Consolas", 12), text_color="#00FF00")
log_box.pack(fill="both", expand=True, padx=10, pady=5)

lbl_alerts = ctk.CTkLabel(main_frame, text="INTRUSION ALERTS", font=("Roboto", 14, "bold"), text_color="#FF5555")
lbl_alerts.pack(pady=5, anchor="w", padx=10)
alert_box = ctk.CTkTextbox(main_frame, width=600, height=100, font=("Consolas", 12), text_color="#FF5555", border_color="#FF5555", border_width=1)
alert_box.pack(fill="x", padx=10, pady=(0, 10))

init_db()
app.mainloop()
