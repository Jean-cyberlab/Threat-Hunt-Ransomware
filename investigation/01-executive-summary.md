# 📋 Executive Summary

## Incident Overview

On 27 January 2026, Ashford Sterling Recruitment — a small recruitment firm with 45 employees — suffered a ransomware attack carried out by the **Akira ransomware group**. The attack was a continuation of a prior compromise ("The Broker") in which an initial access broker had pre-staged persistent access via AnyDesk remote access software.

The threat actor returned using this pre-staged access, deployed tooling from a custom C2 infrastructure, disabled security controls, harvested credentials, moved laterally to the file server, exfiltrated sensitive data, and deployed Akira ransomware — all within approximately **3 hours**.

---

## Scope of Compromise

| Host | Role | Impact |
|---|---|---|
| `as-pc2` | User workstation (David Mitchell) | Initial foothold, credential theft, tool staging |
| `as-srv` | File server | Lateral movement target, data exfiltration, ransomware deployment |

---

## Attack Narrative

### Phase 1 — Re-Entry via Pre-Staged Access
The threat actor connected to `as-pc2` using **AnyDesk** that had been installed during a prior compromise. AnyDesk was running from `C:\Users\Public` — an unusual, world-writable location chosen to avoid detection. The attacker's real IP address (`88.97.164.155`) was exposed via a direct connection on AnyDesk's port 7070, bypassing relay obfuscation.

### Phase 2 — Tool Deployment
The attacker first attempted to download tools using **bitsadmin.exe** (a Windows LOLBIN) but encountered issues. They switched to **PowerShell's Invoke-WebRequest** to successfully pull `wsync.exe` (C2 beacon) and `scan.exe` (AdvancedIpScanner) from `sync.cloud-endpoint.net`. Both files were staged in `C:\ProgramData\`.

### Phase 3 — Defense Evasion
The evasion script **kill.bat** was deployed and executed, disabling Windows Defender real-time monitoring via `Set-MpPreference`. The registry key `DisableAntiSpyware` was set to `1` under the Windows Defender policy path. The Windows Firewall was also disabled using `netsh advfirewall set allprofiles state off`. Volume shadow copies were deleted to prevent file recovery.

### Phase 4 — Credential Theft
The attacker enumerated running processes using `tasklist | findstr lsass` to locate the LSASS process. Credentials were dumped from LSASS memory via the named pipe `\Device\NamedPipe\lsass`, providing password hashes for all accounts on the machine — including the `as.srv.administrator` local admin account.

### Phase 5 — Lateral Movement
Using the harvested `as.srv.administrator` credentials, the attacker authenticated to the file server `as-srv`. Network share enumeration was performed against two internal hosts (`10.1.0.154` and `10.1.0.183`) to map accessible shares.

### Phase 6 — Data Exfiltration
On `as-srv`, the staging tool `st.exe` compressed sensitive data into `exfil_data.zip` at `C:\Users\Public\` — consistent with Akira's double extortion model of stealing data before encrypting it.

### Phase 7 — Ransomware Deployment & Cleanup
The Akira ransomware binary was deployed as `updater.exe` (disguised as a Windows update process) from `C:\ProgramData\`. Encryption began at **22:18:33 UTC**, targeting `C:\Shares` and appending the `.akira` extension to all files. Ransom notes (`akira_readme.txt`) were dropped in each encrypted directory. Two minutes later, `clean.bat` deleted `updater.exe` and the PowerShell command history (`ConsoleHost_history.txt`) to hinder forensic investigation.

---

## Business Impact

- **Data encrypted:** All files in `C:\Shares` including Backups, Clients, Compliance, Contractors, and Payroll folders
- **Data stolen:** Financial documents, employee personal information, customer databases, contracts, and internal communications
- **Ransom demand:** £65,000 (initial), with a counter-offer of £11,000 from the victim
- **Recovery options:** Limited — shadow copies deleted, backups potentially encrypted
- **Deadline:** 72 hours before data published on Akira's leak site

---

## Key IOCs

| Type | Value |
|---|---|
| Threat Actor | Akira Ransomware Group |
| Attacker IP | `88.97.164.155` |
| C2 Domain | `sync.cloud-endpoint.net` |
| Staging Domain | `cdn.cloud-endpoint.net` |
| C2 IPs | `104.21.30.237`, `172.67.174.46` |
| Ransomware Binary | `updater.exe` |
| Ransomware Hash | `e609d070ee9f76934d73353be4ef7ff34b3ecc3a2d1e5d052140ed4cb9e4752b` |
| File Extension | `.akira` |
| Ransom Note | `akira_readme.txt` |

---

## Recommendations Summary

1. **Immediate:** Isolate and reimage `as-pc2` and `as-srv`, reset all compromised credentials, block all IOC domains and IPs
2. **Short-term:** Enable Defender Tamper Protection, deploy Credential Guard, restrict execution from `C:\Users\Public` and `C:\ProgramData`
3. **Long-term:** Implement MFA for all remote access, deploy immutable offline backups, conduct regular threat hunts for pre-staged access tools
