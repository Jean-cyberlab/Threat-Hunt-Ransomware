# 🔍 KQL Query Library

A collection of KQL queries developed during the Akira ransomware threat hunt investigation. All queries are written for **Microsoft Defender for Endpoint Advanced Hunting**.

---

## Query Files

| File | Description |
|---|---|
| [network-hunting.kql](network-hunting.kql) | C2 domain detection, exfil traffic, AnyDesk connections |
| [process-hunting.kql](process-hunting.kql) | Malicious process execution, LOLBins, scanner tools |
| [credential-theft.kql](credential-theft.kql) | LSASS access, named pipes, logon events |
| [defense-evasion.kql](defense-evasion.kql) | Defender tampering, registry, firewall, VSS deletion |
| [ransomware-detection.kql](ransomware-detection.kql) | Encryption events, ransom notes, cleanup scripts |

---

## MDE Tables Used

| Table | Purpose |
|---|---|
| `DeviceProcessEvents` | Process creation, command line arguments |
| `DeviceFileEvents` | File creation, modification, deletion, hashes |
| `DeviceNetworkEvents` | Network connections, URLs, IPs, ports |
| `DeviceLogonEvents` | Authentication events, logon types, source IPs |
| `DeviceRegistryEvents` | Registry key creation, modification, deletion |
| `DeviceEvents` | Named pipes, PowerShell commands, other OS events |

---

## Key KQL Concepts Used

```kql
// Time filtering
| where Timestamp between (datetime(2026-01-27T19:00:00) .. datetime(2026-01-27T23:00:00))

// Case-insensitive match
| where FileName =~ "anydesk.exe"

// Multiple value matching
| where FileName has_any ("wsync.exe", "scan.exe", "updater.exe")

// JSON parsing from AdditionalFields
| extend PipeName = parse_json(AdditionalFields).PipeName

// Summarise and count
| summarize count() by DeviceName, FileName

// Sort results
| sort by Timestamp asc
```
