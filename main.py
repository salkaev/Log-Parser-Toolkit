# ==================== auth.log (SSH / Linux) ====================
# Extract user and IP from failed password attempts
# Failed password for (\S+) from (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})
#
# Extract user and IP from failed password attempts (including "invalid user" prefix)
# (?:invalid user )?(\S+) from (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})
#
# Extract only IP from failed password attempts
# from (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})
#
# Extract user and IP from successful logins
# Accepted password for (\S+) from (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})

# ==================== access.log (Apache) ====================
# Extract HTTP method, URL, and status code
# "(\S+) (\S+) HTTP/1\.1" (\d{3})
#
# Extract HTTP method, URL, status code, and User-Agent
# "(\S+) (\S+) HTTP/1\.1" (\d{3}) \d+ "([^"]+)"
#
# Extract only User-Agent (last quoted field)
# "([^"]+)" "$"

# ==================== Apache error.log ====================
# Extract module name, error code, IP address, and port
# \[(\S+):\S+\]\s+.*?refused:\s+(\S+):\s+.*?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d+)

# ==================== Nginx error.log ====================
# Extract file path and client IP from failed open() calls
# open\(\)\s"([^"]+)"\sfailed.+client:\s(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})

# ==================== DHCP ====================
# Extract DHCP server IP, client IP, and MAC address
# DHCPACK from (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) to (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) \((([a-fA-F0-9]{2}:){5}[a-fA-F0-9]{2})\)

# ==================== DNS log (dnsmasq) ====================
# Extract subdomain, domain, and source IP
# query\s\S+\s(\S+)\.(\S+)\sfrom\s(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})

# ==================== Squid Proxy ====================
# Extract source IP, destination IP, protocol, and source port
# SRC=(\S+) DST=(\S+) PROTO=(\S+) SPT=(\S+)
#
# Extract source IP, method, domain:port, and destination IP (CONNECT tunnel)
# \S+\s(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s\S+\s\S+\s(\S+)\s(\S+)\s\S+/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})

# ==================== Windows Firewall ====================
# Extract action, protocol, source IP, and destination port
# (\S+)\s+(\S+)\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+\S+\s+\S+\s+(\S+)

# ==================== iptables ====================
# Extract action, source IP, protocol, and source port
# kernel: (\S+) .+ SRC=((?:\d{1,3}\.){3}\d{1,3}) .+ PROTO=(\S+) SPT=(\S+)

# ==================== Kerberos (Event ID 4768) ====================
# Extract username, domain, and IP address
# user:\s+(\S+)@(\S+)\s+from IP:\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})

# ==================== Postfix (email) ====================
# Extract sender IP, sender address, and recipient address
# from \S+\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\] from=<(\S+)> to=<(\S+)>

# ==================== FTP ====================
# Extract username, source IP, and destination IP
# User: (\S+), Source IP: (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}), Destination: (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})

# ==================== OpenVPN ====================
# Extract client IP, client port, and username
# for (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\S+) username '(\S+)'

# ==================== PowerShell (Event ID 4104) ====================
# Extract URL, output file path, and launch command
# -Uri (\S+) -OutFile (\S+); Start-Process (\S+)

# ==================== MySQL ====================
# Extract username and IP address from access denied errors
# Access denied for user '(\S+)'@'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'

# ==================== Sysmon Event ID 3 ====================
# Extract process image, source IP, destination IP, and destination port
# Image:\s(\S+),.+SourceIp:\s(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}),DestinationIp:\s(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}),DestinationPort:\s(\d+)

# ==================== Suricata IDS ====================
# Extract signature, classification, source IP, destination IP, and destination port
# \[\*\*\]\s\[[^\]]+\]\s(.+?)\s\[\*\*\]\s\[Classification:\s(.+?)\]\s.*?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):\d+\s->\s(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d+)

# ==================== Docker ====================
# Extract username and IP address from auth errors
# user\s"([^"]+)"\sfrom\s(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})

# ==================== IIS (Microsoft Exchange) ====================
# Extract source IP, HTTP method, URL, username, and status code
# (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+(\S+)\s+(\S+)\s+\S+\s+(\S+)\s+.*?\s+(\d{3})\s+

import re
from Evtx.Evtx import Evtx
import xml.etree.ElementTree as ET
import json
import time
import vt

choice = 0
print("LOG PARSER TOOLKIT - Select log type")
print("1. auth.log (SSH/Linux)")
print("2. access.log (Apache)")
print("3. error.log (Apache)")
print("4. nginx_error.log (Nginx)")
print("5. dhcp.log (DHCP)")
print("6. dns.log (DNS)")
print("7. squid.log (Squid Proxy)")
print("8. firewall.log (Windows Firewall)")
print("9. iptables.log)")
print("10. kerberos.log)")
print("11. postfix.log (Email)")
print("12. ftp.log)")
print("13. openvpn.log)")
print("14. powershell.log)")
print("15. mysql.log)")
print("16. sysmon.log)")
print("17. suricata.log)")
print("18. docker.log)")
print("19. iis.log (IIS)")
print("What is the name of your log?")
match choice:
    case "1":
        print("You selected auth.log (SSH/Linux)")
        # Parse SSH auth log for failed/successful logins
    case "2":
        print("You selected access.log (Apache)")
        # Parse Apache access log for HTTP methods, URLs, status codes
    case "3":
        print("You selected error.log (Apache)")
        # Parse Apache error log for errors and IP addresses
    case "4":
        print("You selected nginx_error.log (Nginx)")
        # Parse Nginx error log for file paths and client IPs
    case "5":
        print("You selected dhcp.log (DHCP)")
        # Parse DHCP log for IP and MAC addresses
    case "6":
        print("You selected dns.log (DNS)")
        # Parse DNS log for subdomains, domains and source IPs
    case "7":
        print("You selected squid.log (Squid Proxy)")
        # Parse Squid proxy log for source/destination IPs and ports
    case "8":
        print("You selected firewall.log (Windows Firewall)")
        # Parse Windows Firewall log for actions, protocols, IPs and ports
    case "9":
        print("You selected iptables.log")
        # Parse iptables log for actions, IPs, protocols and ports
    case "10":
        print("You selected kerberos.log")
        # Parse Kerberos log for usernames, domains and IP addresses
    case "11":
        print("You selected postfix.log (Email)")
        # Parse Postfix log for sender IP, sender and recipient addresses
    case "12":
        print("You selected ftp.log")
        # Parse FTP log for usernames, source and destination IPs
    case "13":
        print("You selected openvpn.log")
        # Parse OpenVPN log for client IP, port and username
    case "14":
        print("You selected powershell.log")
        # Parse PowerShell log for URLs, output files and launch commands
    case "15":
        print("You selected mysql.log")
        # Parse MySQL log for usernames and IPs from access denied errors
    case "16":
        print("You selected sysmon.log")
        # Parse Sysmon Event ID 3 for process images and network connections
    case "17":
        print("You selected suricata.log")
        # Parse Suricata IDS logs for signatures and IP/port details
    case "18":
        print("You selected docker.log")
        # Parse Docker log for usernames and IPs from auth errors
    case "19":
        print("You selected iis.log (IIS)")
        # Parse IIS log for source IPs, HTTP methods, URLs and status codes
    case _:
        print("Error: Invalid choice! Please enter a number from 1 to 19.")



# Converting EVTX to JSON
with Evtx('evtx.evtx') as evtx:
    events = []
    for record in evtx.records():
        events.append(record.xml())

with open('events.json', 'w', encoding='utf-8') as f:
    json.dump(events, f, indent=2, ensure_ascii=False)

# Reading JSON and finding the event ID
with open('events.json', 'r', encoding='utf-8') as f:
    events = json.load(f)