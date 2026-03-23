# 🔍 Threat Hunt: Akira Ransomware 

![Status](https://img.shields.io/badge/Status-Complete-brightgreen)
![Difficulty](https://img.shields.io/badge/Difficulty-Advanced-red)
![Tool](https://img.shields.io/badge/Tool-Microsoft%20Defender%20for%20Endpoint-0078D4)

---

## 📋 Overview

This repository documents a complete threat hunt investigation into an **Akira ransomware** attack.

The investigation required working **backwards from ransomware impact**, tracking attacker activity across multiple hosts, correlating pre-staged infrastructure from a prior compromise, and answering 40 investigative flags using **Microsoft Defender for Endpoint (MDE)** and **KQL**.

---

## 🎯 Challenge Summary

| Field | Detail |
|---|---|
| **Challenge** | The Akira Ransomeware |
| **Difficulty** | Advanced |
| **Tool** | Microsoft Defender for Endpoint |
| **Query Language** | KQL (Kusto Query Language) |
| **Flags Completed** | 40 / 40 |
| **Threat Actor** | Akira Ransomware Group |
| **Incident Date** | 27 January 2026 |

---

## 🗂️ Repository Structure

```
├── README.md                        ← You are here
├── investigation/
│   ├── 01-executive-summary.md      ← High-level attack overview
│   ├── 02-attack-timeline.md        ← Full chronological timeline
│   ├── 03-flags-walkthrough.md      ← All 40 flags with methodology
│   └── 04-mitre-mapping.md          ← MITRE ATT&CK technique mapping
├── kql-queries/
│   ├── README.md                    ← Query library overview
│   ├── network-hunting.kql          ← C2, exfil, domain queries
│   ├── process-hunting.kql          ← Malicious process queries
│   ├── credential-theft.kql         ← LSASS, pipe, logon queries
│   ├── defense-evasion.kql          ← Defender, registry, firewall
│   └── ransomware-detection.kql     ← Encryption, note, cleanup
└── iocs/
    ├── README.md                    ← IOC context and usage
    ├── domains.txt                  ← Malicious domains
    ├── ip-addresses.txt             ← Attacker and C2 IPs
    ├── file-hashes.txt              ← SHA256 hashes
    └── iocs-full.csv                ← Complete IOC reference
```

---

## ⚡ Attack Summary

A ransomware affiliate re-entered the environment using **pre-staged AnyDesk** access from a prior compromise, downloaded tools via PowerShell from a custom C2 domain, dumped credentials from LSASS, moved laterally to the file server, and deployed a ransomware — all within approximately **3 hours**.

```
[AnyDesk Pre-Staged] → [Tools Downloaded] → [Defender Disabled]
        ↓
[LSASS Dumped] → [Lateral Movement] → [Data Exfiltrated]
        ↓
[Ransomware Deployed] → [Files Encrypted] → [Evidence Deleted]
```

---

## 🔑 Key Findings

- **Pre-staged access** from prior compromise reused via AnyDesk (`C:\Users\Public`)
- **Attacker IP** `88.97.164.155` identified via AnyDesk direct connection on port 7070
- **Windows Defender disabled** via `kill.bat` and registry modification (`DisableAntiSpyware`)
- **LSASS credentials dumped** via `\Device\NamedPipe\lsass` named pipe
- **Lateral movement** to file server using harvested `as.srv.administrator` credentials
- **Data exfiltrated** and compressed into `exfil_data.zip` before encryption
- **Akira ransomware** deployed as `updater.exe` — disguised as a Windows update process
- **Encryption began** at `22:18:33 UTC` targeting `C:\Shares`
- **Ransom demand:** £65,000 with 72-hour deadline

---

## 🗺️ MITRE ATT&CK Techniques

| ID | Technique |
|---|---|
| T1133 | External Remote Services (AnyDesk) |
| T1197 | BITS Jobs (bitsadmin.exe) |
| T1105 | Ingress Tool Transfer |
| T1059.001 | PowerShell (Invoke-WebRequest) |
| T1562.001 | Disable or Modify Security Tools |
| T1112 | Modify Registry |
| T1003.001 | LSASS Memory Dumping |
| T1046 | Network Service Discovery |
| T1021.002 | SMB Lateral Movement |
| T1560 | Archive Collected Data |
| T1486 | Data Encrypted for Impact |
| T1490 | Inhibit System Recovery |
| T1070 | Indicator Removal |

---

## 🔧 Tools & Skills Demonstrated

- **Microsoft Defender for Endpoint** — Advanced Hunting, Process Trees, Alert Investigation
- **KQL** — 6 tables: `DeviceProcessEvents`, `DeviceFileEvents`, `DeviceNetworkEvents`, `DeviceLogonEvents`, `DeviceRegistryEvents`, `DeviceEvents`
- **Threat Intelligence** — ransomware.live, CISA advisories, vendor reports
- **MITRE ATT&CK** — technique identification and mapping
- **IOC Documentation** — hashes, domains, IPs, filenames
- **Timeline Reconstruction** — correlating events across multiple hosts

---

## 📁 Quick Links

- [Executive Summary](investigation/01-executive-summary.md)
- [Attack Timeline](investigation/02-attack-timeline.md)
- [Full Flag Walkthrough](investigation/03-flags-walkthrough.md)
- [MITRE ATT&CK Mapping](investigation/04-mitre-mapping.md)
- [KQL Query Library](kql-queries/README.md)
- [IOC Reference](iocs/README.md)

---

> ⚠️ **Disclaimer:** This investigation was conducted in a controlled lab environment as part of a cybersecurity training challenge.
