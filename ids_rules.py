IDS_SIGNATURES = [
	{
		"name": "SQL Injection (Union)",
		"pattern": b"UNION SELECT",
		"desc": "Attempt to retrieve hidden database data"
	},
	{
		"name": "SQL Injection (Generic)",
		"pattern": b"OR 1=1",
		"desc": "Attempt to bypass authentication logic"
	},
	{
		"name": "XSS (Script Tag)",
		"pattern": b"<script>",
		"desc": "Cross-Site Scripting attempt to run code in browser"
	},
	{
		"name": "Directory Traversal",
		"pattern": b"../",
		"desc": "Attempt to access files outside the web root"
	},
	{
		"name": "Password File Access",
		"pattern": b"/etc/passwd",
		"desc": "Attempt to read Linux user account list"
	},

	# malwalre shellcode section
	{
		"name": "Metasploit Shell",
		"pattern": b"stdapi_sys_config_getuid",
		"desc": "Common Meterpreter payload string"
	},
	{
		"name": "PHP Webshell",
		"pattern": b"<?php system(",
		"desc": "Attempt to execute system commands via PHP"
	},
	{
		"name": "Nmap Scan (XMAS)",
		"pattern": b"\x00\x00\x00\x00\x00\x00",
		"desc": "Potential Reconnaissance Scan"
	}
]

def check_signatures(payload):
	payload_lower = payload.lower()

	for sig in IDS_SIGNATURES:
		pattern = sig["pattern"].lower()

		if pattern in payload_lower:
			return sig["name"], sig["desc"]

	return None, None
