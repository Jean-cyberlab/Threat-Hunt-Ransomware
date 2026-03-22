# 🔴 Indicators of Compromise (IOCs)

All IOCs identified during the Akira ransomware investigation of Ashford Sterling Recruitment.

> ⚠️ **Warning:** Do not browse to any domains or IPs listed here. Do not upload hashes to public sandboxes without authorisation.

---

## IOC Files

| File | Contents |
|---|---|
| [domains.txt](domains.txt) | Malicious domains and subdomains |
| [ip-addresses.txt](ip-addresses.txt) | Attacker and C2 IP addresses |
| [file-hashes.txt](file-hashes.txt) | SHA256 hashes of malicious files |
| [iocs-full.csv](iocs-full.csv) | Complete IOC reference in CSV format |

---

## Quick Reference

### Domains
| Domain | Purpose |
|---|---|
| `sync.cloud-endpoint.net` | Payload hosting (wsync.exe, scan.exe) |
| `cdn.cloud-endpoint.net` | Ransomware staging (updater.exe) |
| `relay-0b975d23.net.anydesk.com` | AnyDesk relay infrastructure |
| `akiral2iz6a7qgd3ayp3l6yub7xx2uep76idk3u2kollpj5z3z636bad.onion` | Akira negotiation portal (TOR) |

### IP Addresses
| IP | Purpose |
|---|---|
| `88.97.164.155` | Attacker's real IP (AnyDesk port 7070) |
| `104.21.30.237` | C2 IP (Cloudflare CDN) |
| `172.67.174.46` | C2 IP (Cloudflare CDN) |

### File Hashes (SHA256)
| Filename | Hash |
|---|---|
| `updater.exe` | `e609d070ee9f76934d73353be4ef7ff34b3ecc3a2d1e5d052140ed4cb9e4752b` |
| `wsync.exe` (v1) | `66b876c52946f4aed47dd696d790972ff265b6f4451dab54245bc4ef1206d90b` |
| `wsync.exe` (v2) | `0072ca0d0adc9a1b2e1625db4409f57fc32b5a09c414786bf08c4d8e6a073654` |
| `kill.bat` | `0e7da57d92eaa6bda9d0bbc24b5f0827250aa42f295fd056ded50c6e3c3fb96c` |
| `scan.exe` | `26d5748ffe6bd95e3fee6ce184d388a1a681006dc23a0f08d53c083c593c193b` |
| `st.exe` | `512a1f4ed9f512572608c729a2b89f44ea66a40433073aedcd914bd2d33b7015` |

---

## Defensive Actions

### Block at Firewall/Proxy
```
sync.cloud-endpoint.net
cdn.cloud-endpoint.net
cloud-endpoint.net (entire domain)
88.97.164.155
104.21.30.237
172.67.174.46
```

### Block by Hash (EDR/AV)
```
e609d070ee9f76934d73353be4ef7ff34b3ecc3a2d1e5d052140ed4cb9e4752b
66b876c52946f4aed47dd696d790972ff265b6f4451dab54245bc4ef1206d90b
0072ca0d0adc9a1b2e1625db4409f57fc32b5a09c414786bf08c4d8e6a073654
0e7da57d92eaa6bda9d0bbc24b5f0827250aa42f295fd056ded50c6e3c3fb96c
26d5748ffe6bd95e3fee6ce184d388a1a681006dc23a0f08d53c083c593c193b
512a1f4ed9f512572608c729a2b89f44ea66a40433073aedcd914bd2d33b7015
```

### Hunt for Filenames
```
wsync.exe
scan.exe
updater.exe (in C:\ProgramData\)
kill.bat
clean.bat
st.exe
exfil_data.zip
akira_readme.txt
```
