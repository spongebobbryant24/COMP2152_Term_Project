# COMP2152 Term Project

## Team Name
SOLO-CTF-Research

## Team Members
> This repository is completed by one student.

| Member | Vulnerability | Branch |
|--------|--------------|--------|
| Jamshaid Mirpour | Insecure HTTP on api.0x10.cloud | jamshaid_insecure_http |
| Jamshaid Mirpour | Server Header Disclosure on api.0x10.cloud | jamshaid_header_disclosure |
| Jamshaid Mirpour | Insecure Service Port Exposure on telnet.0x10.cloud | jamshaid_insecure_service |

## Vulnerability Summaries
1. **Insecure HTTP on `api.0x10.cloud`** 
   The target responds over plain HTTP and does not force HTTPS. This is a security risk because traffic could be intercepted in cleartext.

2. **Server Header Disclosure on `api.0x10.cloud`**  
   The target exposes its `Server` header as `cloudflare`. This reveals implementation details that can help attackers profile the service.

3. **Insecure Service Port Exposure on `telnet.0x10.cloud`**  
      The target has multiple risky service ports open, including 2323, 2121, 2525, and 6379. Open services can increase attack surface and may expose sensitive data or insecure protocols.


## Repository Files
- `insecure_http_check.py`
- `header_disclosure_check.py`
- `insecure_port_check.py`
- `README.md`
- `.gitignore`

## Videos
- Video 1: paste your YouTube link here
- Video 2: paste your YouTube link here
- Video 3: paste your YouTube link here

## How to Run

### 1) Insecure HTTP check
```bash
python3 insecure_http_check.py
```

### 2) Header disclosure check
```bash
python3 header_disclosure_check.py
```

### 3) Insecure service port check
```bash
python3 insecure_port_check.py
```

## Notes
- Only scan **subdomains of 0x10.cloud**.
- Do **not** scan `submit.0x10.cloud` or `ranking.0x10.cloud`.
- Keep your scripts and commit history clean.

