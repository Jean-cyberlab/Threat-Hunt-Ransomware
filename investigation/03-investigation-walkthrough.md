# 🔍 Investigation Walkthrough — Akira Ransomware

**Incident Date:** 27 January 2026
**Tool:** Microsoft Defender for Endpoint — Advanced Hunting (KQL)

> All timestamps are in **UTC**. This walkthrough documents my investigative process — what evidence I found, what it revealed about the attacker's behaviour, and how I uncovered it.

---

## 1. Where I Started — Working Backwards From Impact

My investigation began at the point of impact. The file server `as-srv` had been encrypted with the `.akira` extension appended to every file, and ransom notes named `akira_readme.txt` had been dropped across multiple directories inside `C:\Shares`. This told me immediately who was responsible — the Akira ransomware group — and gave me a clear timestamp to work backwards from.

The ransom note contained a TOR address for victim negotiations and a unique victim ID. When I attempted to verify the TOR address, I ran into a common problem — the font used in the note made several characters visually ambiguous, with lowercase `l` characters easily mistaken for the number `1`. I cross-referenced the address against [ransomware.live](https://www.ransomware.live), a public threat intelligence resource that tracks ransomware group infrastructure, to confirm the correct address. Three positions in the address had been misread — `akira[l]2`, `ayp3[l]6`, and `ko[ll]pj` were all lowercase L, not the number one.

![File server encrypted files](images/image1.png)

![Ransom note content](images/image2.png)

![Encrypted files view](images/image3.png)

My first KQL query was simple — find the ransom note to confirm the file server hostname and establish the exact time encryption began:

```kql
DeviceFileEvents
| where FileName == "akira_readme.txt"
| project Timestamp, DeviceName, FolderPath
| sort by Timestamp asc
```

![Ransom note timestamps](images/image5.png)

The first ransom note was dropped at **22:18:33 UTC** on 27 January 2026. This became my primary timestamp anchor — everything I investigated from this point was working backwards from this moment.

---

## 2. Re-Entry — Pre-Staged Access via AnyDesk

The challenge brief told me this was a return visit — the attacker had previously compromised the environment and left behind persistent access. My first task was to find how they got back in.

I searched network events for connections to known remote access tool infrastructure. AnyDesk connections appeared immediately, originating from `as-pc2` — a user workstation belonging to `david.mitchell`. I then queried for the `anydesk.exe` process to see where it was running from:

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

This was a significant finding. Legitimate AnyDesk installations live in `C:\Program Files (x86)\AnyDesk\`. This instance was running from `C:\Users\Public` — a world-writable directory accessible to any user without elevated privileges, hidden from default Windows Explorer views. This confirmed AnyDesk had been manually dropped here rather than installed — it was pre-staged during a prior compromise and left as a persistent backdoor.

AnyDesk typically routes connections through relay servers, which hides the attacker's true IP. However, when a direct connection is possible, AnyDesk uses port 7070 and the real source IP is exposed. I filtered AnyDesk network events to public IPs:

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

Three connections on port 7070 all came from the same external IP — **88.97.164.155**. This is the attacker's real IP address. I also found the relay domain being used when direct connections weren't possible:

```kql
DeviceNetworkEvents
| where DeviceName in ("as-pc2", "as-srv")
| where Timestamp between (datetime(2026-01-27T13:00:00) .. datetime(2026-01-27T22:30:00))
| where RemoteUrl contains "relay"
| project Timestamp, DeviceName, RemoteUrl, RemoteIP, RemotePort, InitiatingProcessFileName
| sort by Timestamp asc
```

![AnyDesk relay domain evidence](images/image7.png)

The attacker was back inside the network via a backdoor they had left from a previous intrusion — no new exploitation required.

---

## 3. Tool Deployment & C2 Infrastructure

With access re-established, the attacker's next step was deploying their toolset. I reviewed the MDE process tree for `as-pc2` and found a new executable — `wsync.exe` — acting as the C2 beacon. The name was chosen to mimic a legitimate Windows synchronisation process.

To find where it came from, I queried outbound network connections made by `powershell.exe` — the MDE process tree had already shown PowerShell was being used for remote execution:

```kql
DeviceNetworkEvents
| where DeviceName == "as-pc2"
| where InitiatingProcessFileName == "powershell.exe"
| where ActionType == "ConnectionSuccess"
| project Timestamp, RemoteUrl, RemoteIP, RemotePort, InitiatingProcessCommandLine
| sort by Timestamp asc
```

![Payload domain evidence](images/image4.png)

The domain `sync.cloud-endpoint.net` appeared as the source of the tool downloads. The name was deliberately chosen to blend in with legitimate cloud traffic. It resolved to two different IPs — `104.21.30.237` and `172.67.174.46` — both belonging to Cloudflare's CDN. Hosting malicious content behind a CDN makes IP-based blocking ineffective and the traffic appear more legitimate to network monitoring tools.

The attacker first attempted to download tools using `bitsadmin.exe` — a Windows built-in (LOLBIN) that is rarely monitored. I found this by reviewing all processes spawned by `wsync.exe`:

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

The same download was attempted multiple times to different paths — `C:\Users\Public\`, `C:\Temp\`, and `C:\Users\david.mitchell\Downloads\` — suggesting permission or path issues. After these failures, the attacker switched to PowerShell's `Invoke-WebRequest` cmdlet. I found this by querying `DeviceEvents` for `PowerShellCommand` action types — individual cmdlet executions are captured here even when not visible in `DeviceProcessEvents`:

```kql
DeviceEvents
| where DeviceName == "as-pc2"
| where Timestamp between (datetime(2026-01-27T20:00:00) .. datetime(2026-01-27T21:00:00))
| where ActionType == "PowerShellCommand"
| project TimeGenerated, DeviceName, ActionType, AdditionalFields
| sort by TimeGenerated asc
```

![Invoke-WebRequest evidence](images/image31.png)

Two tools were downloaded — `wsync.exe` (the C2 beacon) and `scan.exe` (a network scanner). Both were staged in `C:\ProgramData\`.

The beacon was actually deployed twice. When I retrieved the hashes of both `wsync.exe` instances, they were different — confirming the attacker rotated the binary after the first was likely detected by Defender:

```kql
DeviceFileEvents
| where DeviceName == "as-pc2"
| where FileName == "wsync.exe"
| project Timestamp, DeviceName, FileName, SHA256
| sort by Timestamp asc
```

![wsync.exe first hash](images/image23.png)

![wsync.exe second hash](images/image24.png)

The MDE process tree also flagged `scan.exe` as AdvancedIpScanner — a legitimate network administration tool that had been renamed to disguise its identity. I retrieved its hash and confirmed the exact arguments used when it was executed. Finding the arguments required careful attention to the UTC time window — my initial queries failed because I was using local time:

```kql
DeviceProcessEvents
| where DeviceName == "as-pc2"
| where Timestamp between (datetime(2026-01-27T20:15:00) .. datetime(2026-01-27T20:20:00))
| where FileName contains "scan"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName
| sort by Timestamp asc
```

![Scanner arguments evidence](images/image27.png)

The `/portable` flag meant no installation artefacts were left. Output was directed to `C:\Users\david.mitchell\Downloads\` — meaning the scan results were saved locally for the attacker to review through their AnyDesk session.

---

## 4. Defense Evasion

Before proceeding with credential theft, the attacker needed to disable endpoint defences. I found a batch script — `kill.bat` — stored in `C:\ProgramData\` that was responsible for multiple layers of defence evasion. I identified it by searching for process command lines containing "disable":

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

The `InitiatingProcessCommandLine` field showed `cmd.exe /c C:\ProgramData\kill.bat` as the parent for all the disabling commands — this identified the script file. Inside it, `kill.bat` ran several commands to blind the defences:

- `Set-MpPreference -DisableRealtimeMonitoring $true` — disabled Defender real-time monitoring
- `net stop WinDefend`, `WdNisSvc`, `SecurityHealthService` — stopped Defender services
- `netsh advfirewall set allprofiles state off` — disabled the Windows Firewall entirely

But the attacker went further. They also modified the Windows registry to disable Defender at the policy level — a more persistent method that survives reboots:

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

The `DisableAntiSpyware` value was set to `1` under `HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender` at **21:03:42 UTC**. Unlike stopping a service, this registry change persists across reboots — Defender would remain disabled even after a restart until the key was manually removed.

---

## 5. Credential Theft

With defences down, the attacker moved to credential harvesting. Before attempting to access LSASS memory, they first confirmed it was running:

```kql
DeviceProcessEvents
| where DeviceName in ("as-pc2", "as-srv")
| where ProcessCommandLine has_any ("tasklist", "Get-Process", "ps ", "qprocess", "wmic process")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| sort by Timestamp asc
```

![Process hunt evidence](images/image14.png)

The command `tasklist | findstr lsass` was run twice — at 21:11 and 21:14 UTC — both initiated by `wsync.exe`. Running it twice suggested the attacker was being methodical, confirming LSASS was running before proceeding.

The actual credential dump was captured in a MDE alert — "powershell.exe read lsass.exe process memory." This gave me the exact time window and process to focus on. I queried `DeviceEvents` for named pipe events, using `parse_json()` to extract the pipe name from the `AdditionalFields` JSON:

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

The named pipe `\Device\NamedPipe\lsass` was accessed — a direct channel to LSASS process memory. This extracted credential hashes for every logged-in account on the machine, including the `as.srv.administrator` local admin account that would be used moments later for lateral movement.

> The MDE alert was the key that unlocked this finding. Without it, I was searching too broad a time window and returning too much noise. Checking alerts before writing queries is something I now do as a first step.

---

## 6. Lateral Movement to the File Server

With `as.srv.administrator` credentials in hand, the attacker moved from the workstation to the file server. All subsequent activity on `as-srv` was performed under this account — confirmed consistently across every event on that host.

Once on the server, the attacker enumerated network shares on two internal hosts, just one minute before encryption began:

```kql
DeviceProcessEvents
| where DeviceName == "as-srv"
| where Timestamp between (datetime(2026-01-27T20:00:00) .. datetime(2026-01-27T22:30:00))
| where ProcessCommandLine has_any ("net view", "net use", "\\\\", "share")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| sort by Timestamp asc
```

![Network enumeration evidence](images/image28.png)

The commands `net view \\10.1.0.154` and `net view \\10.1.0.183` were executed at 22:17 UTC — 60 seconds before encryption started. The attacker was checking whether these hosts had accessible shares worth targeting. Having admin credentials on the file server gave full control over the environment's most sensitive data.

---

## 7. Data Exfiltration

Before triggering the ransomware, the attacker staged data for exfiltration — this is Akira's double extortion model. Encrypting files alone gives one lever; stealing data first gives a second, independent threat even if the victim recovers from backups.

I found the exfiltration artefacts by searching for archive files created on both hosts in the attack window:

```kql
DeviceFileEvents
| where DeviceName in ("as-pc2", "as-srv")
| where Timestamp between (datetime(2026-01-27T20:00:00) .. datetime(2026-01-27T22:30:00))
| where FileName contains "Zip"
| project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessFileName
| sort by Timestamp asc
```

![Staging tool and archive evidence](images/image32.png)

A tool called `st.exe` created `exfil_data.zip` at `C:\Users\Public\` on the file server. The naming was explicit — there was no attempt to disguise the archive's purpose. I retrieved its hash to add to the IOC list:

```kql
DeviceFileEvents
| where FileName == "st.exe"
| project Timestamp, DeviceName, FileName, FolderPath, SHA256
| sort by Timestamp asc
```

![st.exe hash evidence](images/image33.png)

The archive was placed in `C:\Users\Public\` — the same world-writable directory the attacker had been using throughout. This location was accessible via the AnyDesk session, making exfiltration straightforward without needing additional tools.

---

## 8. Ransomware Deployment & Encryption

With data staged, the attacker deployed the ransomware. I found it by reviewing process events on `as-srv` in the narrow window just before encryption:

```kql
DeviceProcessEvents
| where DeviceName == "as-srv"
| where Timestamp between (datetime(2026-01-27T22:00:00) .. datetime(2026-01-27T22:30:00))
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine
| sort by Timestamp asc
```

![Ransomware filename evidence](images/image34.png)

The ransomware binary was named `updater.exe` and was executed from `C:\ProgramData\` — disguised as a Windows update process to avoid suspicion in process lists. I retrieved its hash:

```kql
DeviceFileEvents
| where DeviceName == "as-srv"
| where FileName == "updater.exe"
| project Timestamp, DeviceName, FileName, FolderPath, SHA256
| sort by Timestamp asc
```

![Ransomware hash evidence](images/image35.png)

I also confirmed what process had dropped `updater.exe` onto the server — the `InitiatingProcessFileName` column in `DeviceFileEvents` answered this:

```kql
DeviceFileEvents
| where DeviceName == "as-srv"
| where FileName == "updater.exe"
| project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine
| sort by Timestamp asc
```

![Ransomware staging evidence](images/image36.png)

Before triggering encryption, the attacker deleted Volume Shadow Copies to eliminate recovery options. I found the commands by searching for "delete" in process command lines:

```kql
DeviceProcessEvents
| where DeviceName in ("as-pc2", "as-srv")
| where Timestamp between (datetime(2026-01-27T20:00:00) .. datetime(2026-01-27T22:30:00))
| where ProcessCommandLine contains "delete"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
| sort by Timestamp asc
```

![Shadow copy deletion evidence](images/image37.png)

The full set of recovery-prevention commands included:
- `vssadmin delete shadows /all /quiet` — silently deleted all shadow copies
- `wmic shadowcopy delete` — additional shadow copy removal
- `bcdedit /set {default} recoveryenabled No` — disabled Windows Recovery
- `sc stop VSS` and `sc stop wbengine` — stopped backup services

Encryption began at **22:18:33 UTC**. The ransomware dropped `akira_readme.txt` in every encrypted directory simultaneously:

```kql
DeviceFileEvents
| where DeviceName == "as-srv"
| where FileName has "akira_readme"
| project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine
| sort by Timestamp asc
```

![Ransom note origin evidence](images/image38.png)

Notes were dropped in the administrator's Desktop, Downloads, and Documents folders — ensuring immediate visibility upon login.

---

## 9. Cleanup & Anti-Forensics

Two minutes after encryption began, the attacker ran a cleanup script. I found it by querying for file deletion events after encryption:

```kql
DeviceFileEvents
| where DeviceName == "as-srv"
| where Timestamp between (datetime(2026-01-27T22:00:00) .. datetime(2026-01-28T00:00:00))
| where ActionType == "FileDeleted"
| project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine
| sort by Timestamp asc
```

![Cleanup script evidence](images/image39.png)

The script `clean.bat` deleted two items:

1. **`updater.exe`** — removing the ransomware binary makes malware analysis harder and reduces the chance of automated tools finding it
2. **`ConsoleHost_history.txt`** — this is PowerShell's command history file. Deleting it erases a record of every command the attacker ran during the intrusion

This is deliberate anti-forensics behaviour — the attacker understood how incident responders work and attempted to remove the most accessible evidence artefacts before leaving.

---

## 10. Scope, Impact & Timeline

### Compromised Hosts

| Host | Role | Key Actions |
|---|---|---|
| `as-pc2` | Initial foothold | AnyDesk re-entry, tool staging, credential theft, defense evasion |
| `as-srv` | Primary target | Lateral movement, data exfiltration, ransomware deployment, encryption |

### Full Attack Timeline

| Time (UTC) | Host | Activity |
|---|---|---|
| 19:15 | as-pc2 | AnyDesk executed from `C:\Users\Public` — attacker re-enters |
| 19:17 | as-pc2 | bitsadmin.exe attempts tool downloads (fails) |
| 19:17 | as-pc2 | Invoke-WebRequest downloads `scan.exe` and `wsync.exe` |
| 19:22 | as-pc2 | `wsync.exe` C2 beacon deployed to `C:\ProgramData\` |
| 19:17 | as-pc2 | `scan.exe` (AdvancedIpScanner) executed — internal network mapped |
| 20:03 | as-pc2 | `kill.bat` executed — Defender real-time monitoring disabled |
| 20:03 | as-pc2 | Security services stopped via `net stop` commands |
| 20:09 | as-pc2 | Windows Firewall disabled |
| 20:09 | as-pc2 | Shadow copies deleted — recovery options removed |
| 20:44 | as-pc2 | `wsync.exe` v2 deployed (beacon rotation after first blocked) |
| 21:03 | as-pc2 | `DisableAntiSpyware` registry key set — Defender policy disabled |
| 21:11 | as-pc2 | `tasklist \| findstr lsass` — LSASS process confirmed running |
| 21:14 | as-pc2 | LSASS memory read via `\Device\NamedPipe\lsass` — credentials stolen |
| 22:17 | as-srv | Lateral movement — `as.srv.administrator` authenticates to file server |
| 22:17 | as-srv | `net view \\10.1.0.154` and `net view \\10.1.0.183` — shares enumerated |
| 22:17 | as-srv | `st.exe` creates `exfil_data.zip` — data compressed for exfiltration |
| 22:18 | as-srv | `updater.exe` deployed — Akira ransomware staged |
| **22:18:33** | as-srv | **Encryption begins** — `.akira` extension appended to all files |
| 22:18:33 | as-srv | `akira_readme.txt` dropped in encrypted directories |
| 22:20 | as-srv | `clean.bat` deletes `updater.exe` and PowerShell history |

### Total Dwell Time
From first attacker activity at **19:15 UTC** to encryption at **22:18 UTC** — approximately **3 hours 3 minutes**.

### Business Impact
- All files in `C:\Shares` encrypted — Backups, Clients, Compliance, Contractors, and Payroll folders
- Sensitive data exfiltrated before encryption — financial records, employee data, client databases
- Shadow copies destroyed — no easy local recovery path
- Ransom demand of £65,000 issued with a 72-hour deadline

---

## Key Investigative Lessons

**1. Start from impact and work backwards**
Beginning at the ransom note gave me a timestamp anchor and a hostname. Every subsequent query built on that foundation.

**2. Check MDE alerts before writing queries**
The alert "powershell.exe read lsass.exe process memory" saved significant time — it directed me to the exact time window and process for the credential theft investigation rather than hunting blindly.

**3. Always work in UTC**
Several of my early queries returned empty results because I was using local time. MDE stores all timestamps in UTC — always convert before writing a time filter.

**4. The `DeviceEvents` table captures what others miss**
Individual PowerShell cmdlet executions aren't always visible in `DeviceProcessEvents`. Querying `DeviceEvents` with `ActionType == "PowerShellCommand"` was essential for finding the `Invoke-WebRequest` downloads.

**5. Parent process context is everything**
The `InitiatingProcessCommandLine` and `InitiatingProcessFileName` columns repeatedly provided the missing link — connecting malicious commands back to the script or tool that called them.

---

## Recommendations Summary

1. **Immediate:** Isolate and reimage `as-pc2` and `as-srv`, reset all compromised credentials, block all IOC domains and IPs
2. **Short-term:** Enable Defender Tamper Protection, deploy Credential Guard, restrict execution from `C:\Users\Public` and `C:\ProgramData`
3. **Long-term:** Implement MFA for all remote access, deploy immutable offline backups, conduct regular threat hunts for pre-staged access tools
