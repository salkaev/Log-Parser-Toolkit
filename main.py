import re
from Evtx.Evtx import Evtx
import xml.etree.ElementTree as ET
import json
import time
import vt
import requests

print("Enter your virustotal api key")
API = input()

def virustotal_api(IP):

    url = f'https://www.virustotal.com/api/v3/ip_addresses/{IP}'

    headers = {
        'accept': 'application/json',
        'x-apikey': API
    }
    request = requests.get(url, headers=headers)
    data = request.json()
    print(data["data"]["attributes"]["last_analysis_stats"])

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
    for x in filtered:
         for y in x:
            pattern_ip = re.compile(r'\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}')
            match = pattern_ip.search(y)
            if match != None:
                virustotal_api(y)
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
        print("You selected auth.log (SSH/Linux)")

        # Parse SSH auth log for failed/successful logins
        patterns = [
            re.compile(r'Failed password for invalid user (\S+) from (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'), # "Failed password for invalid user admin from 185.143.22.10"
            re.compile(r'Failed password for (\S+) from (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'), # "Failed password for root from 185.143.22.10"
            re.compile(r'Invalid user (\S+) from (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'), # "Invalid user admin from 185.143.22.10"
            re.compile(r'Accepted password for (\S+) from (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'), # "Accepted password for ilya from 192.168.1.15"
]
        parse_log_file(patterns)

    case "2":
        print("You selected access.log (Apache)")
        # Parse Apache access log for HTTP methods, URLs, status codes
        patterns = [
            re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) - - \[.+\] "(GET) (.+1=1.*) HTTP\S+" (\d{3})'),# 192.168.1.100 - - [10/Oct/2026:13:55:36 +0000] "GET /products.php?id=1 OR 1=1 HTTP/1.1" 200 5120
            re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) - - \[.+\] "(GET) (.+1=2.*) HTTP\S+" (\d{3})'),# 203.0.113.5 - - [10/Oct/2026:13:55:37 +0000] "GET /user.php?id=1 AND 1=2 HTTP/1.1" 500 256
            re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) - - \[.+\] "(GET) (\S+) HTTP\S+" (\d{3})'), # 192.168.1.100 - - [10/Oct/2026:13:55:38 +0000] "GET /search.php?q=admin' HTTP/1.1" 500 128
            re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) - - \[.+\] "(\S{3,4}) (\S+) HTTP\S+" (\d{3})')# 192.168.2.20 - - [28/Jul/2006:10:27:10 -0300] "GET /cgi-bin/try/ HTTP/1.0" 200 3395
    ]
        parse_log_file(patterns)
    case "3":
        print("You selected error.log (Apache)")
        # Parse Apache error log for errors and IP addresses
        patterns = [
            re.compile(r'\[.+\] (\[ssl:error\]) \[.+\] (AH01961: SSL Proxy requested for unknown host)'),#[Wed Jun 11 14:00:05.123456 2026] [ssl:error] [pid 1234:tid 1234] [client 185.143.22.10:54323] AH01961: SSL Proxy requested for unknown host
            re.compile(r'\[.+\] (\[auth_basic:error\]) \[.+\] (\d+:) (\S+), referer: (\S+)'),#[Wed Jun 11 14:00:04.123456 2026] [auth_basic:error] [pid 1234:tid 1234] [client 185.143.22.10:54322] user admin not found, referer: http://185.143.22.10/admin
            re.compile(r'\[.+\] (\[cgi:error\]) \[.+\] \(2\)(.+:) (\S+), referer: (\S+)'),#[Wed Jun 11 14:00:02.123456 2026] [cgi:error] [pid 1234:tid 1234] (2)Script not found or unable to stat: /usr/lib/cgi-bin/test.cgi, referer: http://185.143.22.10/
            re.compile(r'\[.+\] (\[.+:error\]) \[.+\] \(2\)(\d+:) \S+, referer: (\S+)')#[Wed Jun 11 14:00:02.123456 2026] [core:error] [pid 1234:tid 1234] (2)File does not exist: /var/www/html/admin, referer: http://185.143.22.10/
        ]
        parse_log_file(patterns)

    case "4":
        # Parse Nginx log nginx_error.log
        print("You selected nginx_error.log (Nginx)")
        patterns = [
            re.compile(r'\[.+\] \[error\] \d+#\d+: \*\d+ SSL_do_handshake\(\) failed \(SSL: error:.*?\), client: (\S+)'),# [Wed Jun 11 14:00:05.123456 2026] [error] 1234#1234: *12345 SSL_do_handshake() failed (SSL: error:1408F10B:SSL routines:ssl3_get_record:wrong version number), client: 185.143.22.10
            re.compile(r'\[.+\] \[error\] \d+#\d+: \*\d+ SSL Proxy requested for unknown host, client: (\S+)'),# [Wed Jun 11 14:00:05.123456 2026] [error] 1234#1234: *12345 SSL Proxy requested for unknown host, client: 185.143.22.10
            re.compile(r'\[.+\] \[error\] \d+#\d+: \*\d+ user "(\S+)" not found, client: (\S+), server: (\S+), request: "(\S+) (\S+) HTTP/\d\.\d+", host: "(\S+)"'),# [Wed Jun 11 14:00:04.123456 2026] [error] 1234#1234: *12345 user "admin" not found, client: 185.143.22.10, server: example.com, request: "GET /admin HTTP/1.1", host: "185.143.22.10"
            re.compile(r'\[.+\] \[error\] \d+#\d+: \*\d+ open\(\) "(\S+)" failed \(13: Permission denied\), client: (\S+), server: (\S+), request: "(\S+) (\S+) HTTP/\d\.\d+", host: "(\S+)"'),# [Wed Jun 11 14:00:04.123456 2026] [error] 1234#1234: *12345 open() "/etc/passwd" failed (13: Permission denied), client: 185.143.22.10, server: example.com, request: "GET /../../etc/passwd HTTP/1.1", host: "185.143.22.10"
            re.compile(r'\[.+\] \[error\] \d+#\d+: \*\d+ open\(\) "(\S+)" failed \(2: No such file or directory\), client: (\S+), server: (\S+), request: "(\S+) (\S+) HTTP/\d\.\d+", host: "(\S+)"'),# [Wed Jun 11 14:00:02.123456 2026] [error] 1234#1234: *12345 open() "/var/www/html/.env" failed (2: No such file or directory), client: 185.143.22.10, server: example.com, request: "GET /.env HTTP/1.1", host: "185.143.22.10"
            re.compile(r'\[.+\] \[error\] \d+#\d+: \*\d+ directory index of "(\S+)" is forbidden, client: (\S+), server: (\S+), request: "(\S+) (\S+) HTTP/\d\.\d+", host: "(\S+)"'),# [Wed Jun 11 14:00:03.123456 2026] [error] 1234#1234: *12345 directory index of "/var/www/html/admin" is forbidden, client: 185.143.22.10, server: example.com, request: "GET /admin/ HTTP/1.1", host: "185.143.22.10"
            re.compile(r'\[.+\] \[error\] \d+#\d+: \*\d+ limiting requests, excess: (\d+\.\d+) by zone "(\S+)", client: (\S+), server: (\S+), request: "(\S+) (\S+) HTTP/\d\.\d+", host: "(\S+)"'),# [Wed Jun 11 14:00:03.123456 2026] [error] 1234#1234: *12345 limiting requests, excess: 5.123 by zone "perip", client: 185.143.22.10, server: example.com, request: "GET / HTTP/1.1", host: "185.143.22.10"
            re.compile(r'\[.+\] \[error\] \d+#\d+: \*\d+ client intended to send too large (?:body|header): (\d+) bytes, client: (\S+), server: (\S+), request: "(\S+) (\S+) HTTP/\d\.\d+", host: "(\S+)"'),# [Wed Jun 11 14:00:03.123456 2026] [error] 1234#1234: *12345 client intended to send too large body: 1073741824 bytes, client: 185.143.22.10, server: example.com, request: "POST /upload HTTP/1.1", host: "185.143.22.10"
            re.compile(r'\[.+\] \[error\] \d+#\d+: \*\d+ upstream timed out \((\d+: Connection timed out|110: Connection timed out)\) while (?:reading|connecting to) upstream, client: (\S+), server: (\S+), request: "(\S+) (\S+) HTTP/\d\.\d+", upstream: "(\S+)", host: "(\S+)"'),# [Wed Jun 11 14:00:03.123456 2026] [error] 1234#1234: *12345 upstream timed out (110: Connection timed out) while reading response header from upstream, client: 185.143.22.10, server: example.com, request: "GET /api/users HTTP/1.1", upstream: "http://127.0.0.1:9000", host: "185.143.22.10"
            re.compile(r'\[.+\] \[error\] \d+#\d+: \*\d+ client sent invalid (?:method|header|request) while reading client request line, client: (\S+), server: (\S+), request: "(\S+) (\S+) HTTP/\d\.\d+", host: "(\S+)"'),# [Wed Jun 11 14:00:03.123456 2026] [error] 1234#1234: *12345 client sent invalid method "FOO" while reading client request line, client: 185.143.22.10, server: example.com, request: "FOO / HTTP/1.1", host: "185.143.22.10"
            re.compile(r'open() "(/S+)" failed ')
        ]
        parse_log_file(patterns)

    case "5":
        # Parse DHCP log for IP and MAC addresses
        print("You selected dhcp.log (DHCP)")
        patterns = [
            # Jun 18 14:00:05 dhcpd: DHCPDISCOVER from 00:11:22:33:44:55 via eth0: no free leases
            re.compile(r'\S+ \d+ \d+:\d+:\d+ \S+ dhcpd: DHCPDISCOVER from (\S+) via \S+: no free leases'),# [Jun 18 14:00:05] dhcpd: DHCPDISCOVER from 00:11:22:33:44:55 via eth0: no free leases
            # Jun 18 14:00:05 dhcpd: DHCPDISCOVER from 00:11:22:33:44:55 via eth0: network 192.168.1.0/24: no free leases
            re.compile(r'\S+ \d+ \d+:\d+:\d+ \S+ dhcpd: DHCPDISCOVER from (\S+) via \S+: network \S+: no free leases'),# [Jun 18 14:00:05] dhcpd: DHCPDISCOVER from 00:11:22:33:44:55 via eth0: network 192.168.1.0/24: no free leases
            # Jun 18 14:00:05 dhcpd: DHCPACK to 192.168.1.100 (00:11:22:33:44:55) via eth0: address already in use by 66:77:88:99:AA:BB
            re.compile(r'\S+ \d+ \d+:\d+:\d+ \S+ dhcpd: DHCPACK to \S+ \((\S+)\) via \S+: address already in use by (\S+)'),# [Jun 18 14:00:05] dhcpd: DHCPACK to 192.168.1.100 (00:11:22:33:44:55) via eth0: address already in use by 66:77:88:99:AA:BB
            # Jun 18 14:00:05 dhcpd: DHCPREQUEST for 192.168.1.101 from 00:11:22:33:44:55 via eth0: lease not found
            re.compile(r'\S+ \d+ \d+:\d+:\d+ \S+ dhcpd: DHCPREQUEST for \S+ from (\S+) via \S+: lease not found'),# [Jun 18 14:00:05] dhcpd: DHCPREQUEST for 192.168.1.101 from 00:11:22:33:44:55 via eth0: lease not found
            # Jun 18 14:00:05 dhcpd: DHCPINFORM from 00:11:22:33:44:55 via eth0: unknown subnet
            re.compile(r'\S+ \d+ \d+:\d+:\d+ \S+ dhcpd: DHCPINFORM from (\S+) via \S+: unknown subnet'),# [Jun 18 14:00:05] dhcpd: DHCPINFORM from 00:11:22:33:44:55 via eth0: unknown subnet
            # Jun 18 14:00:05 dhcpd: DHCP lease for IP 192.168.1.101 is greater than pool size
            re.compile(r'\S+ \d+ \d+:\d+:\d+ \S+ dhcpd: DHCP lease for IP \S+ is greater than pool size'),# [Jun 18 14:00:05] dhcpd: DHCP lease for IP 192.168.1.101 is greater than pool size
            # Jun 18 14:00:05 dhcpd: failed to write database /var/lib/dhcp/dhcpd.leases: No space left on device
            re.compile(r'\S+ \d+ \d+:\d+:\d+ \S+ dhcpd: failed to write database \S+: (?:No space left on device|Permission denied|Read-only file system)'),# [Jun 18 14:00:05] dhcpd: failed to write database /var/lib/dhcp/dhcpd.leases: No space left on device
            # Jun 18 14:00:05 dhcpd: DHCP server not configured to serve this client (00:11:22:33:44:55)
            re.compile(r'\S+ \d+ \d+:\d+:\d+ \S+ dhcpd: DHCP server not configured to serve this client \((\S+)\)'),# [Jun 18 14:00:05] dhcpd: DHCP server not configured to serve this client (00:11:22:33:44:55)
            # Jun 18 14:00:05 dhcpd: multiple DHCP servers detected on network (IP 192.168.1.250)
            re.compile(r'\S+ \d+ \d+:\d+:\d+ \S+ dhcpd: multiple DHCP servers detected on network \(IP (\S+)\)'),# [Jun 18 14:00:05] dhcpd: multiple DHCP servers detected on network (IP 192.168.1.250)
            # Jun 18 14:00:05 dhcpd: DHCP packet received on interface eth0 with invalid option
            re.compile(r'\S+ \d+ \d+:\d+:\d+ \S+ dhcpd: DHCP packet received on interface \S+ with invalid option'),# [Jun 18 14:00:05] dhcpd: DHCP packet received on interface eth0 with invalid option
            # Jun 18 14:00:05 kernel: [12345.678901] DHCP-snooping: Packet from unauthorized server 192.168.1.250 dropped on port eth0
            re.compile(r'\S+ \d+ \d+:\d+:\d+ \S+ kernel: \[.*?\] DHCP-snooping: Packet from unauthorized server (\S+) dropped on port \S+'),# [Jun 18 14:00:05] kernel: [12345.678901] DHCP-snooping: Packet from unauthorized server 192.168.1.250 dropped on port eth0
            # Jun 18 14:00:05 dhcpd: Refusing binding for client 00:11:22:33:44:55 on subnet 192.168.1.0/24 with lease time 0
            re.compile(r'\S+ \d+ \d+:\d+:\d+ \S+ dhcpd: Refusing binding for client (\S+) on subnet \S+ with lease time 0'),# [Jun 18 14:00:05] dhcpd: Refusing binding for client 00:11:22:33:44:55 on subnet 192.168.1.0/24 with lease time 0
            # Jun 18 14:00:05 dhcpd: possible DHCP starvation attack from MAC 00:11:22:33:44:55 (1000 requests in 10 seconds)
            re.compile(r'\S+ \d+ \d+:\d+:\d+ \S+ dhcpd: possible DHCP starvation attack from MAC (\S+) \(\d+ requests in \d+ seconds\)'),# [Jun 18 14:00:05] dhcpd: possible DHCP starvation attack from MAC 00:11:22:33:44:55 (1000 requests in 10 seconds)
]
        parse_log_file(patterns)

    case "6":
        # Parse dns.log
        print("You selected dns.log (DNS)")
        patterns = [
            # Jun 18 14:00:05 named[12345]: client 185.143.22.10#54321: query: example.com IN A + (192.168.1.1)
            re.compile(r'\S+ \d+ \d+:\d+:\d+ \S+ named\[\d+\]: client (\S+)#\d+: query: \S+ IN A \+ \(\S+\)'),# [Jun 18 14:00:05] named[12345]: client 185.143.22.10#54321: query: example.com IN A + (192.168.1.1)
            # Jun 18 14:00:05 named[12345]: client 185.143.22.10#54321: query: example.com IN AAAA + (192.168.1.1)
            re.compile(r'\S+ \d+ \d+:\d+:\d+ \S+ named\[\d+\]: client (\S+)#\d+: query: \S+ IN AAAA \+ \(\S+\)'),# [Jun 18 14:00:05] named[12345]: client 185.143.22.10#54321: query: example.com IN AAAA + (192.168.1.1)
            # Jun 18 14:00:05 named[12345]: client 185.143.22.10#54321: query: example.com IN TXT + (192.168.1.1)
            re.compile(r'\S+ \d+ \d+:\d+:\d+ \S+ named\[\d+\]: client (\S+)#\d+: query: \S+ IN TXT \+ \(\S+\)'),# [Jun 18 14:00:05] named[12345]: client 185.143.22.10#54321: query: example.com IN TXT + (192.168.1.1)
            # Jun 18 14:00:05 named[12345]: client 185.143.22.10#54321: query: example.com IN ANY + (192.168.1.1)
            re.compile(r'\S+ \d+ \d+:\d+:\d+ \S+ named\[\d+\]: client (\S+)#\d+: query: \S+ IN ANY \+ \(\S+\)'),# [Jun 18 14:00:05] named[12345]: client 185.143.22.10#54321: query: example.com IN ANY + (192.168.1.1)
            # Jun 18 14:00:05 named[12345]: client 185.143.22.10#54321: request for AXFR of zone "example.com" from 192.168.1.1 (denied)
            re.compile(r'\S+ \d+ \d+:\d+:\d+ \S+ named\[\d+\]: client (\S+)#\d+: request for AXFR of zone "(\S+)" from \S+ \(denied\)'),# [Jun 18 14:00:05] named[12345]: client 185.143.22.10#54321: request for AXFR of zone "example.com" from 192.168.1.1 (denied)
            # Jun 18 14:00:05 named[12345]: client 185.143.22.10#54321: transfer of zone "example.com" denied
            re.compile(r'\S+ \d+ \d+:\d+:\d+ \S+ named\[\d+\]: client (\S+)#\d+: transfer of zone "(\S+)" denied'),# [Jun 18 14:00:05] named[12345]: client 185.143.22.10#54321: transfer of zone "example.com" denied
            # Jun 18 14:00:05 named[12345]: validation failure (example.com IN A): signature expired
            re.compile(r'\S+ \d+ \d+:\d+:\d+ \S+ named\[\d+\]: validation failure \((\S+) IN A\): signature expired'),# [Jun 18 14:00:05] named[12345]: validation failure (example.com IN A): signature expired
            # Jun 18 14:00:05 named[12345]: validation failure (example.com IN A): bogus DNSSEC signature
            re.compile(r'\S+ \d+ \d+:\d+:\d+ \S+ named\[\d+\]: validation failure \((\S+) IN A\): bogus DNSSEC signature'),# [Jun 18 14:00:05] named[12345]: validation failure (example.com IN A): bogus DNSSEC signature
            # Jun 18 14:00:05 named[12345]: client 185.143.22.10#54321: query size 65535 bytes denied
            re.compile(r'\S+ \d+ \d+:\d+:\d+ \S+ named\[\d+\]: client (\S+)#\d+: query size \d+ bytes denied'),# [Jun 18 14:00:05] named[12345]: client 185.143.22.10#54321: query size 65535 bytes denied
            # Jun 18 14:00:05 named[12345]: client 185.143.22.10#54321: request too large (65535 bytes), closing connection
            re.compile(r'\S+ \d+ \d+:\d+:\d+ \S+ named\[\d+\]: client (\S+)#\d+: request too large \(\d+ bytes\), closing connection'),# [Jun 18 14:00:05] named[12345]: client 185.143.22.10#54321: request too large (65535 bytes), closing connection
            # Jun 18 14:00:05 named[12345]: client 185.143.22.10#54321: query: example.com IN UNKNOWN123 + (192.168.1.1)
            re.compile(r'\S+ \d+ \d+:\d+:\d+ \S+ named\[\d+\]: client (\S+)#\d+: query: \S+ IN UNKNOWN\d+ \+ \(\S+\)'),# [Jun 18 14:00:05] named[12345]: client 185.143.22.10#54321: query: example.com IN UNKNOWN123 + (192.168.1.1)
            # Jun 18 14:00:05 named[12345]: client 185.143.22.10#54321: query: 127.0.0.1 IN A + (192.168.1.1)
            re.compile(r'\S+ \d+ \d+:\d+:\d+ \S+ named\[\d+\]: client (\S+)#\d+: query: \d+\.\d+\.\d+\.\d+ IN A \+ \(\S+\)'),# [Jun 18 14:00:05] named[12345]: client 185.143.22.10#54321: query: 127.0.0.1 IN A + (192.168.1.1)
            # Jun 18 14:00:05 named[12345]: client 185.143.22.10#54321: query: localhost IN A + (192.168.1.1)
            re.compile(r'\S+ \d+ \d+:\d+:\d+ \S+ named\[\d+\]: client (\S+)#\d+: query: localhost IN A \+ \(\S+\)'),# [Jun 18 14:00:05] named[12345]: client 185.143.22.10#54321: query: localhost IN A + (192.168.1.1)
            # Jun 18 14:00:05 named[12345]: client 192.168.1.100#54321: query: xk23jf9s8df.example.com IN A + (192.168.1.1)
            re.compile(r'\S+ \d+ \d+:\d+:\d+ \S+ named\[\d+\]: client (\S+)#\d+: query: [a-z0-9]{10,}\.\S+ IN A \+ \(\S+\)'),# [Jun 18 14:00:05] named[12345]: client 192.168.1.100#54321: query: xk23jf9s8df.example.com IN A + (192.168.1.1)
            # Jun 18 14:00:05 named[12345]: client 192.168.1.100#54321: query: this-domain-does-not-exist-12345.com IN A + (192.168.1.1)
            re.compile(r'\S+ \d+ \d+:\d+:\d+ \S+ named\[\d+\]: client (\S+)#\d+: query: \S+ IN A \+ \(\S+\)'),# [Jun 18 14:00:05] named[12345]: client 192.168.1.100#54321: query: this-domain-does-not-exist-12345.com IN A + (192.168.1.1)
            # Jun 18 14:00:05 named[12345]: client 192.168.1.100#54321: query: malware-domain-xyz.com IN A + (192.168.1.1)
            re.compile(r'\S+ \d+ \d+:\d+:\d+ \S+ named\[\d+\]: client (\S+)#\d+: query: \S+ IN A \+ \(\S+\)'),# [Jun 18 14:00:05] named[12345]: client 192.168.1.100#54321: query: malware-domain-xyz.com IN A + (192.168.1.1)
            # Jun 18 14:00:05 named[12345]: client 185.143.22.10#54321: query: example.com IN MX + (192.168.1.1)
            re.compile(r'\S+ \d+ \d+:\d+:\d+ \S+ named\[\d+\]: client (\S+)#\d+: query: \S+ IN MX \+ \(\S+\)'),# [Jun 18 14:00:05] named[12345]: client 185.143.22.10#54321: query: example.com IN MX + (192.168.1.1)
            # Jun 18 14:00:05 named[12345]: client 185.143.22.10#54321: query: example.com IN NS + (192.168.1.1)
            re.compile(r'\S+ \d+ \d+:\d+:\d+ \S+ named\[\d+\]: client (\S+)#\d+: query: \S+ IN NS \+ \(\S+\)'),# [Jun 18 14:00:05] named[12345]: client 185.143.22.10#54321: query: example.com IN NS + (192.168.1.1)
            # Jun 18 14:00:05 named[12345]: client 185.143.22.10#54321: query: example.com IN CNAME + (192.168.1.1)
            re.compile(r'\S+ \d+ \d+:\d+:\d+ \S+ named\[\d+\]: client (\S+)#\d+: query: \S+ IN CNAME \+ \(\S+\)'),# [Jun 18 14:00:05] named[12345]: client 185.143.22.10#54321: query: example.com IN CNAME + (192.168.1.1)
            # Jun 18 14:00:05 named[12345]: client 185.143.22.10#54321: query: example.com IN PTR + (192.168.1.1)
            re.compile(r'\S+ \d+ \d+:\d+:\d+ \S+ named\[\d+\]: client (\S+)#\d+: query: \S+ IN PTR \+ \(\S+\)'),# [Jun 18 14:00:05] named[12345]: client 185.143.22.10#54321: query: example.com IN PTR + (192.168.1.1)
            # Jun 18 14:00:05 named[12345]: client 185.143.22.10#54321: query: example.com IN SOA + (192.168.1.1)
            re.compile(r'\S+ \d+ \d+:\d+:\d+ \S+ named\[\d+\]: client (\S+)#\d+: query: \S+ IN SOA \+ \(\S+\)'),# [Jun 18 14:00:05] named[12345]: client 185.143.22.10#54321: query: example.com IN SOA + (192.168.1.1)
            # Jun 18 14:00:05 named[12345]: client 185.143.22.10#54321: query: example.com IN SRV + (192.168.1.1)
        re.compile(r'\S+ \d+ \d+:\d+:\d+ \S+ named\[\d+\]: client (\S+)#\d+: query: \S+ IN SRV \+ \(\S+\)'),# [Jun 18 14:00:05] named[12345]: client 185.143.22.10#54321: query: example.com IN SRV + (192.168.1.1)
]
        parse_log_file(patterns)

    case "7":
        # Parse Squid proxy log for source/destination IPs and ports
        print("You selected squid.log (Squid Proxy)")
        patterns = [
            # Jun 18 14:00:05.123 12345 192.168.1.100 TCP_DENIED/403 0 CONNECT malicious-site.com:443 - HIER_NONE/- text/html
            re.compile(r'\S+ \d+ \d+:\d+:\d+\.\d+ \d+ (\S+) TCP_DENIED/\d+ \d+ \S+ \S+:\d+'),# [Jun 18 14:00:05.123 12345] 192.168.1.100 TCP_DENIED/403 0 CONNECT malicious-site.com:443 - HIER_NONE/- text/html
            # Jun 18 14:00:05.123 12345 192.168.1.100 TCP_MISS/200 1024 GET http://example.com - HIER_DIRECT/192.168.1.1 text/html
            re.compile(r'\S+ \d+ \d+:\d+:\d+\.\d+ \d+ (\S+) TCP_MISS/\d+ \d+ \S+ (\S+)://(\S+)(?::\d+)?'),# [Jun 18 14:00:05.123 12345] 192.168.1.100 TCP_MISS/200 1024 GET http://example.com - HIER_DIRECT/192.168.1.1 text/html
            # Jun 18 14:00:05.123 12345 192.168.1.100 TCP_TUNNEL/200 0 CONNECT malware-c2.com:443 - HIER_DIRECT/185.143.22.10 -
            re.compile(r'\S+ \d+ \d+:\d+:\d+\.\d+ \d+ (\S+) TCP_TUNNEL/\d+ \d+ CONNECT (\S+):(\d+)'),# [Jun 18 14:00:05.123 12345] 192.168.1.100 TCP_TUNNEL/200 0 CONNECT malware-c2.com:443 - HIER_DIRECT/185.143.22.10 -
            # Jun 18 14:00:05.123 12345 192.168.1.100 TCP_DENIED/403 0 GET http://192.168.1.1/admin - HIER_NONE/- text/html
            re.compile(r'\S+ \d+ \d+:\d+:\d+\.\d+ \d+ (\S+) TCP_DENIED/\d+ \d+ \S+ http://(\S+)(?::\d+)?'),# [Jun 18 14:00:05.123 12345] 192.168.1.100 TCP_DENIED/403 0 GET http://192.168.1.1/admin - HIER_NONE/- text/html
            # Jun 18 14:00:05.123 12345 192.168.1.100 TCP_DENIED/403 0 GET http://www.phishing-site.ru - HIER_NONE/- text/html
            re.compile(r'\S+ \d+ \d+:\d+:\d+\.\d+ \d+ (\S+) TCP_DENIED/\d+ \d+ \S+ http://(\S+)'),# [Jun 18 14:00:05.123 12345] 192.168.1.100 TCP_DENIED/403 0 GET http://www.phishing-site.ru - HIER_NONE/- text/html
            # Jun 18 14:00:05.123 12345 192.168.1.100 TCP_MISS/404 0 GET http://example.com/.env - HIER_DIRECT/192.168.1.1 text/html
            re.compile(r'\S+ \d+ \d+:\d+:\d+\.\d+ \d+ (\S+) TCP_MISS/404 \d+ \S+ http://(\S+)/\.env'),# [Jun 18 14:00:05.123 12345] 192.168.1.100 TCP_MISS/404 0 GET http://example.com/.env - HIER_DIRECT/192.168.1.1 text/html
            # Jun 18 14:00:05.123 12345 192.168.1.100 TCP_MISS/404 0 GET http://example.com/adminer.php - HIER_DIRECT/192.168.1.1 text/html
            re.compile(r'\S+ \d+ \d+:\d+:\d+\.\d+ \d+ (\S+) TCP_MISS/404 \d+ \S+ http://(\S+)/adminer.php'),# [Jun 18 14:00:05.123 12345] 192.168.1.100 TCP_MISS/404 0 GET http://example.com/adminer.php - HIER_DIRECT/192.168.1.1 text/html
            # Jun 18 14:00:05.123 12345 192.168.1.100 TCP_MISS/404 0 GET http://example.com/phpmyadmin/main.php - HIER_DIRECT/192.168.1.1 text/html
            re.compile(r'\S+ \d+ \d+:\d+:\d+\.\d+ \d+ (\S+) TCP_MISS/404 \d+ \S+ http://(\S+)/phpmyadmin'),# [Jun 18 14:00:05.123 12345] 192.168.1.100 TCP_MISS/404 0 GET http://example.com/phpmyadmin/main.php - HIER_DIRECT/192.168.1.1 text/html
            # Jun 18 14:00:05.123 12345 192.168.1.100 TCP_MISS/404 0 GET http://example.com/../../etc/passwd - HIER_DIRECT/192.168.1.1 text/html
            re.compile(r'\S+ \d+ \d+:\d+:\d+\.\d+ \d+ (\S+) TCP_MISS/404 \d+ \S+ http://(\S+)/\.\./\.\./etc/passwd'),# [Jun 18 14:00:05.123 12345] 192.168.1.100 TCP_MISS/404 0 GET http://example.com/../../etc/passwd - HIER_DIRECT/192.168.1.1 text/html
            # Jun 18 14:00:05.123 12345 192.168.1.100 TCP_MISS/404 0 GET http://example.com/?id=1 UNION SELECT - HIER_DIRECT/192.168.1.1 text/html
            re.compile(r'\S+ \d+ \d+:\d+:\d+\.\d+ \d+ (\S+) TCP_MISS/404 \d+ \S+ http://(\S+)\?.*(UNION|SELECT|DROP|INSERT|UPDATE|DELETE|OR 1=1)'),# [Jun 18 14:00:05.123 12345] 192.168.1.100 TCP_MISS/404 0 GET http://example.com/?id=1 UNION SELECT - HIER_DIRECT/192.168.1.1 text/html
            # Jun 18 14:00:05.123 12345 192.168.1.100 TCP_MISS/200 1024 GET http://example.com/xk23jf9s8df.php - HIER_DIRECT/192.168.1.1 text/html
            re.compile(r'\S+ \d+ \d+:\d+:\d+\.\d+ \d+ (\S+) TCP_MISS/\d+ \d+ \S+ http://(\S+)/[a-z0-9]{10,}\.php'),# [Jun 18 14:00:05.123 12345] 192.168.1.100 TCP_MISS/200 1024 GET http://example.com/xk23jf9s8df.php - HIER_DIRECT/192.168.1.1 text/html
            # Jun 18 14:00:05.123 12345 192.168.1.100 TCP_TUNNEL/200 0 CONNECT 192.168.1.1:8080 - HIER_DIRECT/192.168.1.1 -
            re.compile(r'\S+ \d+ \d+:\d+:\d+\.\d+ \d+ (\S+) TCP_TUNNEL/\d+ \d+ CONNECT (\d+\.\d+\.\d+\.\d+):(\d+)'),# [Jun 18 14:00:05.123 12345] 192.168.1.100 TCP_TUNNEL/200 0 CONNECT 192.168.1.1:8080 - HIER_DIRECT/192.168.1.1 -
            # Jun 18 14:00:05.123 12345 192.168.1.100 TCP_TUNNEL/200 0 CONNECT localhost:8080 - HIER_DIRECT/192.168.1.1 -
            re.compile(r'\S+ \d+ \d+:\d+:\d+\.\d+ \d+ (\S+) TCP_TUNNEL/\d+ \d+ CONNECT localhost:(\d+)'),# [Jun 18 14:00:05.123 12345] 192.168.1.100 TCP_TUNNEL/200 0 CONNECT localhost:8080 - HIER_DIRECT/192.168.1.1 -
            # Jun 18 14:00:05.123 12345 192.168.1.100 TCP_TUNNEL/200 0 CONNECT 127.0.0.1:8080 - HIER_DIRECT/192.168.1.1 -
            re.compile(r'\S+ \d+ \d+:\d+:\d+\.\d+ \d+ (\S+) TCP_TUNNEL/\d+ \d+ CONNECT 127\.0\.0\.1:(\d+)'),# [Jun 18 14:00:05.123 12345] 192.168.1.100 TCP_TUNNEL/200 0 CONNECT 127.0.0.1:8080 - HIER_DIRECT/192.168.1.1 -
            # Jun 18 14:00:05.123 12345 192.168.1.100 TCP_MISS/200 0 CONNECT http://example.com - HIER_DIRECT/192.168.1.1 text/html
            re.compile(r'\S+ \d+ \d+:\d+:\d+\.\d+ \d+ (\S+) TCP_MISS/\d+ \d+ \S+ http://(\S+)(?::\d+)?'),# [Jun 18 14:00:05.123 12345] 192.168.1.100 TCP_MISS/200 0 CONNECT http://example.com - HIER_DIRECT/192.168.1.1 text/html
            # Jun 18 14:00:05.123 12345 192.168.1.100 TCP_MISS/200 0 CONNECT https://example.com - HIER_DIRECT/192.168.1.1 text/html
            re.compile(r'\S+ \d+ \d+:\d+:\d+\.\d+ \d+ (\S+) TCP_MISS/\d+ \d+ \S+ https://(\S+)(?::\d+)?'),# [Jun 18 14:00:05.123 12345] 192.168.1.100 TCP_MISS/200 0 CONNECT https://example.com - HIER_DIRECT/192.168.1.1 text/html
        ]
        parse_log_file(patterns)

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