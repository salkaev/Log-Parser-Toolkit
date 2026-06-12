import re
from Evtx.Evtx import Evtx
import xml.etree.ElementTree as ET
import json
import time
import vt

def parse_log_file(compiled_patterns):
    file_str = []
    my_dict = []
    string = {}
    print("Write a full file path")
    log_file_path = input().strip()
    with open(log_file_path, "r") as file:
        for line in file:
            file_str.append(line)
    
    for line in file_str:
        cnt = file_str.count(line)
        for pattern in compiled_patterns:
            match = pattern.search(line)
            if match != None:
                tuplee = match.groups()
                my_dict.append(tuplee)
    
    for line in my_dict:
        if line not in string:
            string[line] = my_dict.count(line)
        else:
            pass
    
    filtered = {k: v for k, v in string.items()}
    return filtered

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
choice = input()
match choice:
    case "1":
        compiled_patterns = [
    re.compile(r'Failed password for invalid user (\S+) from (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'), # "Failed password for invalid user admin from 185.143.22.10"
    re.compile(r'Failed password for (\S+) from (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'), # "Failed password for root from 185.143.22.10"
    re.compile(r'Invalid user (\S+) from (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'), # "Invalid user admin from 185.143.22.10"
    re.compile(r'Accepted password for (\S+) from (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'), # "Accepted password for ilya from 192.168.1.15"
]
        print("You selected auth.log (SSH/Linux)")
        # Parse SSH auth log for failed/successful logins
        print(parse_log_file(compiled_patterns))


    case "2":

        compiled_patterns = [
re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) - - \[.+\] "(GET) (.+1=1.*) HTTP\S+" (\d{3})'),# 192.168.1.100 - - [10/Oct/2026:13:55:36 +0000] "GET /products.php?id=1 OR 1=1 HTTP/1.1" 200 5120
re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) - - \[.+\] "(GET) (.+1=2.*) HTTP\S+" (\d{3})'),# 203.0.113.5 - - [10/Oct/2026:13:55:37 +0000] "GET /user.php?id=1 AND 1=2 HTTP/1.1" 500 256
re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) - - \[.+\] "(GET) (\S+) HTTP\S+" (\d{3})'), # 192.168.1.100 - - [10/Oct/2026:13:55:38 +0000] "GET /search.php?q=admin' HTTP/1.1" 500 128
re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) - - \[.+\] "(\S{3,4}) (\S+) HTTP\S+" (\d{3})')# 192.168.2.20 - - [28/Jul/2006:10:27:10 -0300] "GET /cgi-bin/try/ HTTP/1.0" 200 3395
    ]
        print("You selected access.log (Apache)")
        # Parse Apache access log for HTTP methods, URLs, status codes
        print(parse_log_file(compiled_patterns))
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
#with Evtx('evtx.evtx') as evtx:
#    events = []
#    for record in evtx.records():
#        events.append(record.xml())

#with open('events.json', 'w', encoding='utf-8') as f:
#    json.dump(events, f, indent=2, ensure_ascii=False)
#
# Reading JSON and finding the event ID
#with open('events.json', 'r', encoding='utf-8') as f:
#    events = json.load(f)