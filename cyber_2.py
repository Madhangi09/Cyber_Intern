import socket
from datetime import datetime

VULN_DB = {
    "OpenSSH_7.2": "Outdated SSH version - update recommended",
    "Apache/2.4.29": "Apache version contains known security issues"
}

COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 443, 3306]


def scan_port(host, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except:
        return False


def get_banner(host, port):
    try:
        s = socket.socket()
        s.settimeout(2)
        s.connect((host, port))
        banner = s.recv(1024).decode(errors="ignore").strip()
        s.close()
        return banner if banner else "Unknown"
    except:
        return "Unknown"


def check_vulnerabilities(banner):
    findings = []
    for software, issue in VULN_DB.items():
        if software in banner:
            findings.append(issue)
    return findings


host = input("Enter target IP/Host: ")

open_ports = []
services = {}
findings = []

for port in COMMON_PORTS:
    if scan_port(host, port):
        open_ports.append(port)

for port in open_ports:
    banner = get_banner(host, port)
    services[port] = banner
    findings.extend(check_vulnerabilities(banner))

if 23 in open_ports:
    findings.append("Telnet service detected")

if 21 in open_ports:
    findings.append("FTP service found - verify anonymous login is disabled")

if 80 in open_ports and 443 not in open_ports:
    findings.append("HTTPS not detected")

report = f"""
VULNERABILITY ASSESSMENT REPORT
================================
Date: {datetime.now()}
Target: {host}

Open Ports:
{open_ports}

Services:
"""

for port, service in services.items():
    report += f"\nPort {port}: {service}"

report += "\n\nFindings:\n"

if findings:
    for item in findings:
        report += f"- {item}\n"
else:
    report += "No obvious vulnerabilities found.\n"

with open("vulnerability_report.txt", "w") as file:
    file.write(report)

print(report)
print("\nReport saved as vulnerability_report.txt")