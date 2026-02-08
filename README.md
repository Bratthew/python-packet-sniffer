This is a raw-socket network analyzer that captures TCP/IP packets on Linux.

This captures raw frames using `socket.AF_PACKET`, unpacks Ethernet, IPv4, and TCP headers manually, and
detects HTTP Basic Auth credentials

run with root privileges:
`sudo python3 sniffer.py`
