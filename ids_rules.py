import re

IDS_SIGNATURES = [
	{
		"name": "Scanner Tool (Nmap)",
		"regex": re.compile(rb"User-Agent:.*Nmap", re.IGNORECASE),
		"desc": "Nmap Scripting Engine detected"
	},
	{
		"name": "Scanner Tool (Nikto)",
		"regex": re.compile(rb"User-Agent:.*Nikto", re.IGNORECASE),
		"desc": "Web Vulnerability Scanner detected"
	},
	{
		"name": "Scanner Tool (Sqlmap)",
		"regex": re.compile(rb"User-Agent:.*sqlmap", re.IGNORECASE),
		"desc": "SQL Injection tool detected"
	},
	{
		"name": "Python Script",
		"regex": re.compile(rb"User-Agent:.*python-requests", re.IGNORECASE),
		"desc": "Potential automated python script"
	},
	{
		"name": "SQL Injection (Union)",
		"regex": re.compile(rb"union\s+select", re.IGNORECASE),
		"desc": "Attempt to retrieve hidden database data"
	},
	{
		"name": "SQL Injection (Generic)",
		"regex": re.compile(rb"or\s+1=1", re.IGNORECASE),
		"desc": "Attempt to bypass authentication logic"
	},
	{
		"name": "XSS (Script Tag)",
		"regex": re.compile(rb"<script.*?>.*?</script>", re.IGNORECASE | re.DOTALL),
		"desc": "Cross-Site Scripting attempt"
	},
	{
		"name": "Directory Traversal",
		"regex": re.compile(rb"\.\./", re.IGNORECASE),
		"desc": "Attempt to access files outside web root"
	},
	{
		"name": "Password File Access",
		"regex": re.compile(rb"/etc/passwd", re.IGNORECASE),
		"desc": "Attempt to read Linux user account list"
	},
	{
		"name": "Metasploit Shell",
		"regex": re.compile(rb"stdapi_sys_config_getuid", re.IGNORECASE),
		"desc": "Common Meterpreter payload string"
	},
	{
		"name": "PHP Webshell",
		"regex": re.compile(rb"<\?php\s+system\(", re.IGNORECASE),
		"desc": "Attempt to execute system commands via PHP"
	}
]

def check_signatures(payload):
	for sig in IDS_SIGNATURES:
		if "regex" in sig:
			if sig["regex"].search(payload):
				return sig["name"], sig["desc"]
	return None, None
