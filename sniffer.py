import socket
import struct
import textwrap

def main():
	conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
	
	print ("[*] Sniffer good, waiting pckt")

	while True:
		raw_data, adrr = conn.recvfrom(65535)

		dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)

		if eth_proto == 8:
			(version, header_length, ttl, proto, src, target, data) = ipv4_packet(data)

			print(f"IPv4 pckt: ")
			print(f"\tSOurce: {src}, Destination: {target}, Protocol: {proto}")

			if proto == 6:
				src_port, dest_port, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data = tcp_segment(data)
				print(f"\tTCP Segment:")
				print(f"\t\tSource POrt: {src_port}, Destination Port: {dest_port}")
				print(f"\t\tFlags: SYN={flag_syn}, ACK={flag_ack}, FIN={flag_fin}")
				
				if len(data) > 0:
					print(f"\t\tData:")
					try:
						print(textwrap.indent(data.decode('utf-8'), '\t\t\t'))
					except:
						print(textwrap.indent(str(data), '\t\t\t'))

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


if __name__ == "__main__":
	main()
