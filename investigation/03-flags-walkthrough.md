# 🚩 Flag Walkthrough — All 40 Flags

Complete investigation walkthrough with evidence screenshots and KQL queries used to answer each flag.

> All timestamps are in **UTC**. Investigation conducted using **Microsoft Defender for Endpoint Advanced Hunting**.

---

## Q1 — Threat Actor
**Identify the ransomware group from the ransom note.**
**Format:** Group name

### ✅ Answer: `Akira`

Identified directly from the ransom note (`akira_readme.txt`). The note was signed "Akira Team", all encrypted files had the `.akira` extension appended, and the TOR address contained `akira` in the domain.

---

## Q2 — Negotiation Portal
**The ransom note provides a contact method.**
**Format:** onion address (without http://)

### ✅ Answer: `akiral2iz6a7qgd3ayp3l6yub7xx2uep76idk3u2kollpj5z3z636bad.onion`

Found by cross-referencing the ransom note against [ransomware.live](https://www.ransomware.live). Character confusion between `1` (one) and `l` (lowercase L) made direct transcription unreliable — three positions contained `l` characters misread as `1`.

> 💡 **Lesson:** Always verify onion addresses against threat intel sources — never rely solely on transcribing from ransom notes.

---

## Q3 — Victim ID
**Each victim receives a unique identifier for negotiations.**
**Format:** ID string

### ✅ Answer: `813R-QWJM-XKIJ`

Found directly in the ransom note: `Your personal ID: 813R-QWJM-XKIJ`. This ID is used to authenticate to the Akira negotiation portal.

---

## Q4 — Encrypted Extension
**Encrypted files have a new extension appended.**
**Format:** Extension

### ✅ Answer: `.akira`

Visible in the file server screenshot — all encrypted files had `.akira` appended to their original filename.

![File server encrypted files](images/image1.png)

![Ransom note content](images/image2.png)

![Encrypted files view](images/image3.png)

---

## Q5 — Payload Domain
**Tools were downloaded from an external domain.**
**Format:** Domain

### ✅ Answer: `sync.cloud-endpoint.net`

**KQL Query:**
```kql
DeviceNetworkEvents
| where DeviceName == "as-pc2"
| where InitiatingProcessFileName == "powershell.exe"
| where ActionType == "ConnectionSuccess"
| project Timestamp, RemoteUrl, RemoteIP, RemotePort, InitiatingProcessCommandLine
| sort by Timestamp asc
```

![Payload domain evidence](images/image4.png)

---

## Q6 — Ransomware Staging
**The payload established outbound connections.**
**Format:** Domain

### ✅ Answer: `cdn.cloud-endpoint.net`

**KQL Query 1 — Find file server name:**
```kql
DeviceFileEvents
| where FileName == "akira_readme.txt"
| project Timestamp, DeviceName, FolderPath
```

![Ransom note file server location](images/image5.png)

**KQL Query 2 — Find staging domain:**
```kql
DeviceNetworkEvents
| where DeviceName == "as-srv"
| where InitiatingProcessFileName == "wsync.exe"
| where ActionType == "ConnectionSuccess"
| project Timestamp, RemoteUrl, RemoteIP, RemotePort, InitiatingProcessCommandLine, ActionType
| sort by Timestamp asc
```

![Staging domain evidence](images/image6.png)

---

## Q7 — C2 IP Addresses
**The C2 infrastructure resolved to multiple IPs.**
**Format:** Comma separated, any order

### ✅ Answer: `104.21.30.237, 172.67.174.46`

Same query as Q5 — two different IPs returned for the same domain, indicating Cloudflare CDN load balancing.

**KQL Query:**
```kql
DeviceNetworkEvents
| where DeviceName == "as-pc2"
| where InitiatingProcessFileName == "powershell.exe"
| where ActionType == "ConnectionSuccess"
| project Timestamp, RemoteUrl, RemoteIP, RemotePort, InitiatingProcessCommandLine
| sort by Timestamp asc
```

![C2 IP addresses evidence](images/image4.png)

---

## Q8 — Remote Tool Relay
**A remote tool routes through relay servers.**
**Format:** Domain

### ✅ Answer: `relay-0b975d23.net.anydesk.com`

**KQL Query:**
```kql
DeviceNetworkEvents
| where DeviceName in ("as-pc2", "as-srv")
| where Timestamp between (datetime(2026-01-27T13:00:00) .. datetime(2026-01-27T22:30:00))
| where RemoteUrl contains "relay"
| project Timestamp, DeviceName, RemoteUrl, RemoteIP, RemotePort, InitiatingProcessFileName
| sort by Timestamp asc
```

![AnyDesk relay domain evidence](images/image7.png)

---

## Q9 — Evasion Script
**A script was used to disable security controls.**
**Format:** Filename

### ✅ Answer: `kill.bat`

**KQL Query:**
```kql
DeviceProcessEvents
| where DeviceName in ("as-pc2", "as-srv")
| where Timestamp between (datetime(2026-01-27T13:00:00) .. datetime(2026-01-27T22:30:00))
| where ProcessCommandLine contains "disable"
| project Timestamp, DeviceName, AccountName, FileName, InitiatingProcessCommandLine, ProcessCommandLine
| sort by Timestamp asc
```

![Evasion script evidence 1](images/image8.png)

![Evasion script evidence 2](images/image9.png)

---

## Q10 — Evasion Hash
**Identify the hash of the evasion script.**
**Format:** SHA256 hash

### ✅ Answer: `0e7da57d92eaa6bda9d0bbc24b5f0827250aa42f295fd056ded50c6e3c3fb96c`

**KQL Query 1 — Get hash:**
```kql
DeviceFileEvents
| where DeviceName in ("as-pc2", "as-srv")
| where FileName == "kill.bat"
| project Timestamp, DeviceName, FileName, FolderPath, SHA256
| sort by Timestamp asc
```

![kill.bat hash query](images/image10.png)

**KQL Query 2 — Verify hash across all hosts:**
```kql
DeviceFileEvents
| where SHA256 == "0e7da57d92eaa6bda9d0bbc24b5f0827250aa42f295fd056ded50c6e3c3fb96c"
| project Timestamp, DeviceName, FileName, FolderPath
```

![Hash verification](images/image11.png)

---

## Q11 — Registry Tampering
**Windows Defender was disabled via registry modification.**
**Format:** Registry value name

### ✅ Answer: `DisableAntiSpyware`

**KQL Query:**
```kql
DeviceRegistryEvents
| where DeviceName in ("as-pc2", "as-srv")
| where Timestamp between (datetime(2026-01-27T13:00:00) .. datetime(2026-01-27T22:30:00))
| where RegistryKey has "Windows Defender"
| project Timestamp, DeviceName, ActionType, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessFileName
| sort by Timestamp asc
```

![Registry tampering evidence 1](images/image12.png)

![Registry tampering evidence 2](images/image13.png)

---

## Q12 — Registry Timestamp
**Determine when the registry was modified.**
**Format:** HH:MM:SS (UTC)

### ✅ Answer: `21:03:42`

Read from the Timestamp field in the Q11 results: `2026-01-27T21:03:42.39698Z`

> 💡 **Lesson:** The `Z` suffix means UTC. Always convert timestamps when building timelines.

---

## Q13 — Process Hunt
**The attacker enumerated running processes to locate a target for credential theft.**
**Format:** Full command

### ✅ Answer: `tasklist | findstr lsass`

**KQL Query:**
```kql
DeviceProcessEvents
| where DeviceName in ("as-pc2", "as-srv")
| where ProcessCommandLine has_any ("tasklist", "Get-Process", "ps ", "qprocess", "wmic process")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| sort by Timestamp asc
```

![Process hunt evidence](images/image14.png)

---

## Q14 — Credential Pipe
**A named pipe was accessed during credential theft activity.**
**Format:** Full pipe path

### ✅ Answer: `\Device\NamedPipe\lsass`

**KQL Query:**
```kql
DeviceEvents
| where DeviceName == "as-pc2"
| where ActionType == "NamedPipeEvent"
| extend ParsedFields = parse_json(AdditionalFields)
| extend PipeName = ParsedFields.PipeName
| extend FileOperation = ParsedFields.FileOperation
| project Timestamp, AccountName, InitiatingProcessFileName, PipeName, FileOperation
| sort by Timestamp asc
```

![Named pipe evidence 1](images/image15.png)

![Named pipe evidence 2](images/image16.png)

![Named pipe evidence 3](images/image17.png)

> 💡 **Lesson:** Check MDE alerts first — the alert "powershell.exe read lsass.exe process memory" directed the query to the correct time window and process.

---

## Q15 — Remote Access Tool
**A remote access tool was pre-staged from the previous attack.**
**Format:** Tool name

### ✅ Answer: `AnyDesk`

**KQL Query:**
```kql
DeviceNetworkEvents
| where DeviceName == "as-pc2"
| where Timestamp between (datetime(2026-01-27) .. datetime(2026-01-27T22:30:00))
| where RemoteUrl has "anydesk"
| project Timestamp, DeviceName, RemoteUrl, RemoteIP, InitiatingProcessFileName
| sort by Timestamp asc
```

![AnyDesk evidence](images/image18.png)

---

## Q16 — Suspicious Execution Path
**The remote access tool was running from an unusual location on AS-PC2.**
**Format:** Full directory path

### ✅ Answer: `C:\Users\Public`

**KQL Query:**
```kql
DeviceProcessEvents
| where DeviceName == "as-pc2"
| where Timestamp between (datetime(2026-01-26) .. datetime(2026-01-27T22:30:00))
| where FileName =~ "anydesk.exe"
| project Timestamp, DeviceName, AccountName, FolderPath, ProcessCommandLine, InitiatingProcessFileName
| sort by Timestamp asc
```

![AnyDesk execution path 1](images/image19.png)

![AnyDesk execution path 2](images/image20.png)

---

## Q17 — Attacker IP
**Identify the attacker's external IP address.**
**Format:** IP address

### ✅ Answer: `88.97.164.155`

**KQL Query:**
```kql
DeviceNetworkEvents
| where DeviceName == "as-pc2"
| where Timestamp between (datetime(2026-01-27T13:00:00) .. datetime(2026-01-27T22:30:00))
| where InitiatingProcessFileName =~ "anydesk.exe"
| where RemoteIPType == "Public"
| project Timestamp, DeviceName, RemoteIP, RemotePort, LocalPort, ActionType
| sort by Timestamp asc
```

![Attacker IP evidence](images/image21.png)

> 💡 **Lesson:** AnyDesk port 7070 is the direct connection port — relay connections hide the real IP, but port 7070 exposes it.

---

## Q18 — Compromised User
**Identify the user account that was compromised.**
**Format:** Username

### ✅ Answer: `david.mitchell`

Present as `AccountName` across all malicious events on as-pc2 throughout the investigation.

---

## Q19 — Primary Beacon
**A new beacon was deployed to replace the pre-staged one.**
**Format:** Filename

### ✅ Answer: `wsync.exe`

**KQL Query:**
```kql
DeviceProcessEvents
| where DeviceName == "as-pc2"
| where FileName contains "wsync.exe"
| project Timestamp, AccountName, FileName, FolderPath
```

![wsync.exe beacon evidence](images/image22.png)

---

## Q20 — Beacon Location
**Identify where the beacon was deployed.**
**Format:** Full directory path

### ✅ Answer: `C:\ProgramData`

Found in the `FolderPath` column from the Q21/Q22 hash query.

---

## Q21 — Beacon Hash
**Identify the hash of the original C2 beacon.**
**Format:** SHA256 hash

### ✅ Answer: `66b876c52946f4aed47dd696d790972ff265b6f4451dab54245bc4ef1206d90b`

**KQL Query:**
```kql
DeviceFileEvents
| where DeviceName == "as-pc2"
| where FileName == "wsync.exe"
| project Timestamp, DeviceName, FileName, SHA256
| sort by Timestamp asc
```

![wsync.exe first hash](images/image23.png)

---

## Q22 — Beacon Creation
**A second beacon was deployed after the first failed.**
**Format:** SHA256 hash

### ✅ Answer: `0072ca0d0adc9a1b2e1625db4409f57fc32b5a09c414786bf08c4d8e6a073654`

Same query as Q21 — second entry showed a different SHA256, confirming beacon rotation.

![wsync.exe second hash](images/image24.png)

---

## Q23 — Scanner Tool
**A network scanner was deployed.**
**Format:** Filename

### ✅ Answer: `scan.exe`

Identified in the MDE process tree — MDE alerted: *"powershell.exe executed AdvancedIpScanner"*. The binary was renamed from `advanced_ip_scanner.exe` to `scan.exe` to avoid detection.

---

## Q24 — Scanner Hash
**Identify the hash of the scanner.**
**Format:** SHA256 hash

### ✅ Answer: `26d5748ffe6bd95e3fee6ce184d388a1a681006dc23a0f08d53c083c593c193b`

**KQL Query:**
```kql
DeviceFileEvents
| where DeviceName == "as-pc2"
| where InitiatingProcessFileName == "powershell.exe"
| where FileName contains "scan"
| project Timestamp, DeviceName, FileName, FolderPath, SHA256, InitiatingProcessFileName
| sort by Timestamp asc
```

![Scanner file evidence](images/image25.png)

![Scanner hash evidence](images/image26.png)

---

## Q25 — Scanner Execution
**The network scanner was executed with specific arguments.**
**Format:** Full arguments as executed

### ✅ Answer: `/portable "C:/Users/david.mitchell/Downloads/" /lng en_us`

**KQL Query:**
```kql
DeviceProcessEvents
| where DeviceName == "as-pc2"
| where Timestamp between (datetime(2026-01-27T20:15:00) .. datetime(2026-01-27T20:20:00))
| where FileName contains "scan"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName
| sort by Timestamp asc
```

![Scanner arguments evidence](images/image27.png)

---

## Q26 — Network Enumeration
**The attacker enumerated network shares on specific hosts.**
**Format:** Comma separated, any order

### ✅ Answer: `10.1.0.154, 10.1.0.183`

**KQL Query:**
```kql
DeviceProcessEvents
| where DeviceName == "as-srv"
| where Timestamp between (datetime(2026-01-27T20:00:00) .. datetime(2026-01-27T22:30:00))
| where ProcessCommandLine has_any ("net view", "net use", "\\\\", "share")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| sort by Timestamp asc
```

![Network enumeration evidence](images/image28.png)

---

## Q27 — Lateral Account
**An account was used to access AS-SRV.**
**Format:** Username

### ✅ Answer: `as.srv.administrator`

Identified in the `AccountName` field from Q26 results — credentials obtained via LSASS dumping in Q14.

---

## Q28 — Download Method
**A living-off-the-land binary was used first but had issues.**
**Format:** Filename

### ✅ Answer: `bitsadmin.exe`

**KQL Query:**
```kql
DeviceProcessEvents
| where DeviceName == "as-pc2"
| where InitiatingProcessFileName contains "wsync.exe"
| where Timestamp between (datetime(2026-01-27T20:00:00) .. datetime(2026-01-27T22:30:00))
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName
| sort by Timestamp asc
```

![bitsadmin download attempts](images/image29.png)

![bitsadmin evidence 2](images/image30.png)

---

## Q29 — Fallback Method
**After the first tool failed, another method was used.**
**Format:** Cmdlet name

### ✅ Answer: `Invoke-WebRequest`

**KQL Query:**
```kql
DeviceEvents
| where DeviceName == "as-pc2"
| where Timestamp between (datetime(2026-01-27T20:00:00) .. datetime(2026-01-27T21:00:00))
| where ActionType == "PowerShellCommand"
| project TimeGenerated, DeviceName, ActionType, AdditionalFields
| sort by TimeGenerated asc
```

![Invoke-WebRequest evidence](images/image31.png)

> 💡 **Lesson:** PowerShell cmdlets are captured in `DeviceEvents` with `ActionType == "PowerShellCommand"` — not always visible in `DeviceProcessEvents`.

---

## Q30 — Staging Tool
**A tool was used to compress data for exfiltration.**
**Format:** Filename

### ✅ Answer: `st.exe`

**KQL Query:**
```kql
DeviceFileEvents
| where DeviceName in ("as-pc2", "as-srv")
| where Timestamp between (datetime(2026-01-27T20:00:00) .. datetime(2026-01-27T22:30:00))
| where FileName contains "Zip"
| project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessFileName
| sort by Timestamp asc
```

![Staging tool evidence](images/image32.png)

---

## Q31 — Staging Hash
**Identify the hash of the staging tool.**
**Format:** SHA256 hash

### ✅ Answer: `512a1f4ed9f512572608c729a2b89f44ea66a40433073aedcd914bd2d33b7015`

**KQL Query:**
```kql
DeviceFileEvents
| where FileName == "st.exe"
| project Timestamp, DeviceName, FileName, FolderPath, SHA256
| sort by Timestamp asc
```

![st.exe hash evidence](images/image33.png)

---

## Q32 — Exfil Archive
**Identify the archive created for exfiltration.**
**Format:** Filename

### ✅ Answer: `exfil_data.zip`

Identified in the Q30 query results — `exfil_data.zip` created by `st.exe` at `C:\Users\Public\` on as-srv.

![Exfil archive evidence](images/image32.png)

---

## Q33 — Ransomware Filename
**The ransomware was disguised as a legitimate process.**
**Format:** Filename

### ✅ Answer: `updater.exe`

**KQL Query:**
```kql
DeviceProcessEvents
| where DeviceName == "as-srv"
| where Timestamp between (datetime(2026-01-27T22:00:00) .. datetime(2026-01-27T22:30:00))
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine
| sort by Timestamp asc
```

![Ransomware filename evidence](images/image34.png)

---

## Q34 — Ransomware Hash
**Identify the hash of the ransomware.**
**Format:** SHA256 hash

### ✅ Answer: `e609d070ee9f76934d73353be4ef7ff34b3ecc3a2d1e5d052140ed4cb9e4752b`

**KQL Query:**
```kql
DeviceFileEvents
| where DeviceName == "as-srv"
| where FileName == "updater.exe"
| project Timestamp, DeviceName, FileName, FolderPath, SHA256
| sort by Timestamp asc
```

![Ransomware hash evidence](images/image35.png)

---

## Q35 — Ransomware Staging
**The ransomware was dropped onto AS-SRV before execution.**
**Format:** Process name

### ✅ Answer: `powershell.exe`

**KQL Query:**
```kql
DeviceFileEvents
| where DeviceName == "as-srv"
| where FileName == "updater.exe"
| project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine
| sort by Timestamp asc
```

![Ransomware staging evidence](images/image36.png)

---

## Q36 — Recovery Prevention
**The attacker deleted backup copies to prevent file recovery.**
**Format:** Full command

### ✅ Answer: `"vssadmin delete shadows /all /quiet"`

**KQL Query:**
```kql
DeviceProcessEvents
| where DeviceName in ("as-pc2", "as-srv")
| where Timestamp between (datetime(2026-01-27T20:00:00) .. datetime(2026-01-27T22:30:00))
| where ProcessCommandLine contains "delete"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
| sort by Timestamp asc
```

![Shadow copy deletion evidence](images/image37.png)

---

## Q37 — Ransom Note Origin
**A ransom note was dropped after encryption began.**
**Format:** Process name

### ✅ Answer: `updater.exe`

**KQL Query:**
```kql
DeviceFileEvents
| where DeviceName == "as-srv"
| where FileName has "akira_readme"
| project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine
| sort by Timestamp asc
```

![Ransom note origin evidence](images/image38.png)

---

## Q38 — Encryption Start
**Determine when encryption began.**
**Format:** HH:MM:SS (UTC)

### ✅ Answer: `22:18:33`

Read from the first `akira_readme.txt` timestamp in Q37 results: `2026-01-27T22:18:33.372Z`

> Files modified before `22:18:33 UTC` on `2026-01-27` may be recoverable from backup.

---

## Q39 — Cleanup Script
**The ransomware binary was deleted after execution.**
**Format:** Filename

### ✅ Answer: `clean.bat`

**KQL Query:**
```kql
DeviceFileEvents
| where DeviceName == "as-srv"
| where Timestamp between (datetime(2026-01-27T22:00:00) .. datetime(2026-01-28T00:00:00))
| where ActionType == "FileDeleted"
| project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine
| sort by Timestamp asc
```

![Cleanup script evidence](images/image39.png)

---

## Q40 — Affected Hosts
**Determine the scope of the compromise.**
**Format:** Hostnames, comma separated, any order

### ✅ Answer: `as-srv, as-pc2`

Determined through the full investigation by correlating activity across both hosts.

| Host | Role | Key Actions |
|---|---|---|
| `as-pc2` | Initial foothold | AnyDesk re-entry, tool download, credential theft, defense evasion |
| `as-srv` | File server target | Lateral movement, data exfiltration, ransomware deployment, encryption |

---

## 📊 Investigation Summary

| Category | Count |
|---|---|
| Flags Completed | 40 / 40 ✅ |
| Hosts Compromised | 2 (as-pc2, as-srv) |
| Unique KQL Queries Written | 35+ |
| MDE Tables Used | 6 |
| Malicious Files Identified | 6 |
| Malicious Domains Found | 3 |
| Attacker IPs Identified | 3 |
