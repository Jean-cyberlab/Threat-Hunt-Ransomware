# 🗺️ MITRE ATT&CK Mapping

Full mapping of observed attacker techniques to the MITRE ATT&CK Enterprise framework.

---

## Attack Flow by Tactic

```
INITIAL ACCESS → EXECUTION → PERSISTENCE → PRIVILEGE ESCALATION
      ↓               ↓            ↓                ↓
   T1133           T1059        T1219             T1078
   T1078           T1197

DEFENSE EVASION → CREDENTIAL ACCESS → DISCOVERY → LATERAL MOVEMENT
       ↓                  ↓               ↓              ↓
    T1562.001          T1003.001        T1057           T1021.002
    T1562.004          T1078            T1046           T1078.003
    T1112                               T1135
    T1036.005
    T1070

COLLECTION → EXFILTRATION → IMPACT
     ↓             ↓           ↓
   T1560         T1041        T1486
                              T1490
                              T1657
```

---

## Full Technique Table

| Tactic | ID | Technique | Sub-Technique | Evidence |
|---|---|---|---|---|
| Initial Access | T1133 | External Remote Services | — | AnyDesk pre-staged from prior compromise |
| Initial Access | T1078 | Valid Accounts | — | david.mitchell account used throughout |
| Execution | T1059.001 | Command and Scripting Interpreter | PowerShell | Invoke-WebRequest, Set-MpPreference, kill.bat |
| Execution | T1197 | BITS Jobs | — | bitsadmin.exe tool download attempts |
| Persistence | T1219 | Remote Access Software | — | AnyDesk running from C:\Users\Public |
| Defense Evasion | T1562.001 | Impair Defenses | Disable or Modify Tools | kill.bat disabling Defender |
| Defense Evasion | T1562.004 | Impair Defenses | Disable or Modify Firewall | netsh advfirewall set allprofiles state off |
| Defense Evasion | T1112 | Modify Registry | — | DisableAntiSpyware = 1 |
| Defense Evasion | T1036.005 | Masquerading | Match Legitimate Name | updater.exe, wsync.exe, scan.exe |
| Defense Evasion | T1070 | Indicator Removal | — | clean.bat deletes updater.exe + PS history |
| Credential Access | T1003.001 | OS Credential Dumping | LSASS Memory | \Device\NamedPipe\lsass |
| Discovery | T1057 | Process Discovery | — | tasklist \| findstr lsass |
| Discovery | T1046 | Network Service Discovery | — | scan.exe (AdvancedIpScanner) |
| Discovery | T1135 | Network Share Discovery | — | net view \\10.1.0.154 / \\10.1.0.183 |
| Lateral Movement | T1021.002 | Remote Services | SMB/Windows Admin Shares | Lateral movement to as-srv |
| Lateral Movement | T1078.003 | Valid Accounts | Local Accounts | as.srv.administrator used on as-srv |
| Collection | T1560 | Archive Collected Data | — | st.exe → exfil_data.zip |
| Command & Control | T1105 | Ingress Tool Transfer | — | wsync.exe, scan.exe, updater.exe downloaded |
| Command & Control | T1090 | Proxy | — | Cloudflare CDN hiding C2 origin |
| Impact | T1486 | Data Encrypted for Impact | — | Akira ransomware encrypting C:\Shares |
| Impact | T1490 | Inhibit System Recovery | — | vssadmin delete shadows /all /quiet |
| Impact | T1657 | Financial Theft | — | £65,000 ransom demand |

---

## Technique Detail

### T1133 — External Remote Services
AnyDesk was installed during the prior "The Broker" compromise and left running as a persistent backdoor. On re-entry, the attacker connected directly using this pre-staged access, bypassing the need for any new exploitation.

**Detection opportunity:** Monitor for AnyDesk (and similar RMM tools) executing from non-standard paths such as `C:\Users\Public`, `C:\Temp`, or `C:\ProgramData`.

---

### T1197 — BITS Jobs
`bitsadmin.exe` was used to attempt file downloads from `sync.cloud-endpoint.net`. Multiple attempts to different paths indicate the attacker was probing for writable directories.

**Detection opportunity:** Alert on `bitsadmin.exe /transfer` commands where the source URL is external and the destination is a user-writable path.

---

### T1562.001 — Disable or Modify Security Tools
`kill.bat` contained multiple Defender-disabling commands including `Set-MpPreference -DisableRealtimeMonitoring $true` and `net stop WinDefend`. This completely blinded endpoint detection before tool execution.

**Detection opportunity:** Enable Defender Tamper Protection. Alert on `Set-MpPreference` with disabling parameters.

---

### T1112 — Modify Registry
`reg.exe` set `DisableAntiSpyware = 1` under `HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender`. This policy-level change persists across reboots.

**Detection opportunity:** Monitor `DeviceRegistryEvents` for writes to the Windows Defender policy path.

---

### T1003.001 — LSASS Memory
PowerShell accessed LSASS memory via the named pipe `\Device\NamedPipe\lsass`. The harvested credentials for `as.srv.administrator` enabled lateral movement to the file server.

**Detection opportunity:** Deploy Credential Guard. Monitor `DeviceEvents` for `NamedPipeEvent` where PipeName contains `lsass`.

---

### T1486 — Data Encrypted for Impact
`updater.exe` (Akira ransomware) encrypted all files in `C:\Shares`, appending the `.akira` extension. Ransom notes were dropped in each directory simultaneously.

**Detection opportunity:** Alert on mass file rename events where a new extension is appended to many files within a short time window.

---

### T1490 — Inhibit System Recovery
Three separate commands were used to prevent recovery:
- `vssadmin delete shadows /all /quiet`
- `wmic shadowcopy delete`
- `bcdedit /set {default} recoveryenabled No`

**Detection opportunity:** Alert on any execution of `vssadmin delete` or `bcdedit` with recovery-disabling parameters.

---

### T1070 — Indicator Removal
`clean.bat` deleted `updater.exe` and `ConsoleHost_history.txt` two minutes after encryption began, removing the ransomware binary and erasing PowerShell command history.

**Detection opportunity:** Monitor `DeviceFileEvents` for deletion of `.exe` files from `C:\ProgramData` and deletion of PowerShell history files.
