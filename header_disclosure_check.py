"""
Author: Jamshaid Mirpour
Vulnerability: Version Disclosure in Headers
Target subdomain: api.0x10.cloud

Description:
Inspects HTTP response headers for values such as Server or X-Powered-By.
Exposing version or framework details helps attackers look up known vulnerabilities.
"""

import urllib.request
import urllib.error


ALLOWED_ROOT = "0x10.cloud"
BLOCKED_SUBDOMAINS = {"submit.0x10.cloud", "ranking.0x10.cloud"}

def validate_target(host: str) -> None:
    if not host.endswith("." + ALLOWED_ROOT):
        raise ValueError("Target is out of scope. Only subdomains of 0x10.cloud are allowed.")
    if host in BLOCKED_SUBDOMAINS:
        raise ValueError("This subdomain is explicitly excluded from scanning.")


TARGET = "api.0x10.cloud"

def check_headers(target: str) -> None:
    validate_target(target)
    url = f"http://{target}"
    print(f"Checking headers on: {url}")

    try:
        response = urllib.request.urlopen(url, timeout=5)
        headers = dict(response.headers)

        server = headers.get("Server", "Not disclosed")
        powered_by = headers.get("X-Powered-By", "Not disclosed")

        print(f"Server: {server}")
        print(f"X-Powered-By: {powered_by}")

        finding = False

        if server != "Not disclosed":
            finding = True
            print("VULNERABILITY: Server header is exposed.")
            print("RISK: Reveals implementation details that can help attackers identify known exploits.")

        if powered_by != "Not disclosed":
            finding = True
            print("VULNERABILITY: X-Powered-By header is exposed.")
            print("RISK: Reveals framework or language details that help attackers profile the target.")

        if not finding:
            print("No version disclosure finding detected in these headers.")
    except urllib.error.HTTPError as e:
        print(f"HTTP error: {e.code} - {e.reason}")
    except urllib.error.URLError as e:
        print(f"URL error: {e.reason}")
    except Exception as e:
        print(f"Unexpected error: {e}")

if __name__ == "__main__":
    check_headers(TARGET)
