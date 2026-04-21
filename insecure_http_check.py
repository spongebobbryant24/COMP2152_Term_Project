"""
Author: Jamshaid Mirpour
Vulnerability: Insecure HTTP
Target subdomain: api.0x10.cloud

Description:
Checks whether a target subdomain is accessible over HTTP and whether it stays on HTTP
instead of enforcing HTTPS. Plain HTTP is a security risk because traffic can be intercepted.
"""

import urllib.request
import urllib.error
import ssl


ALLOWED_ROOT = "0x10.cloud"
BLOCKED_SUBDOMAINS = {"submit.0x10.cloud", "ranking.0x10.cloud"}

def validate_target(host: str) -> None:
    if not host.endswith("." + ALLOWED_ROOT):
        raise ValueError("Target is out of scope. Only subdomains of 0x10.cloud are allowed.")
    if host in BLOCKED_SUBDOMAINS:
        raise ValueError("This subdomain is explicitly excluded from scanning.")


TARGET = "api.0x10.cloud"

def check_http(target: str) -> None:
    validate_target(target)
    url = f"http://{target}"
    print(f"Checking: {url}")

    try:
        response = urllib.request.urlopen(url, timeout=5)
        final_url = response.geturl()
        print(f"Status: {response.status}")
        print(f"Final URL: {final_url}")

        if final_url.startswith("http://"):
            print("VULNERABILITY: Target is still using HTTP and is not forcing HTTPS.")
            print("RISK: Credentials, cookies, and other traffic could be exposed in cleartext.")
        else:
            print("No insecure HTTP finding detected. Target redirected away from HTTP.")
    except urllib.error.HTTPError as e:
        print(f"HTTP error: {e.code} - {e.reason}")
    except urllib.error.URLError as e:
        print(f"URL error: {e.reason}")
    except Exception as e:
        print(f"Unexpected error: {e}")

if __name__ == "__main__":
    check_http(TARGET)
