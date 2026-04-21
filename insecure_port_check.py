"""
Author: Jamshaid Mirpour
Vulnerability: Insecure Service Port Exposure
Target subdomain: telnet.0x10.cloud

Description:
Checks for risky services on ports often associated with insecure or misconfigured services.
Examples from the assignment include 2323 (Telnet), 2121 (FTP), 2525 (SMTP), and 6379 (Redis).
"""

import socket
import time


ALLOWED_ROOT = "0x10.cloud"
BLOCKED_SUBDOMAINS = {"submit.0x10.cloud", "ranking.0x10.cloud"}

def validate_target(host: str) -> None:
    if not host.endswith("." + ALLOWED_ROOT):
        raise ValueError("Target is out of scope. Only subdomains of 0x10.cloud are allowed.")
    if host in BLOCKED_SUBDOMAINS:
        raise ValueError("This subdomain is explicitly excluded from scanning.")


TARGET = "telnet.0x10.cloud"
PORTS_TO_CHECK = {
    2323: "Telnet",
    2121: "FTP",
    2525: "SMTP",
    6379: "Redis",
}

def check_ports(target: str) -> None:
    validate_target(target)
    print(f"Checking target: {target}")

    for port, service_name in PORTS_TO_CHECK.items():
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        try:
            result = sock.connect_ex((target, port))
            if result == 0:
                print(f"VULNERABILITY: Port {port} ({service_name}) is OPEN on {target}")
                print(f"RISK: {service_name} may expose data, credentials, or unnecessary attack surface.")
            else:
                print(f"Port {port} ({service_name}) appears closed on {target}")
        except Exception as e:
            print(f"Error checking port {port}: {e}")
        finally:
            sock.close()
            time.sleep(0.15)

if __name__ == "__main__":
    check_ports(TARGET)
