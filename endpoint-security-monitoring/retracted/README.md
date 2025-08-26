# A Mother's Plea

## 📖 Overview:

My mother Sophie, a leader of a charity organization, reached out to me in a panic, not knowing who else to turn to. She told me that after downloading what she thought was an antivirus installer, her computer suddenly started acting strange. She could no longer open any of her files, and her wallpaper was replaced with a frightening ransom note demanding payment to restore her data.

Overwhelmed, she stepped away to call me. But when she returned, everything seemed to be back to normal—except for one mysterious message telling her to check her Bitcoin wallet. The problem? She had no idea what Bitcoin even was.

It was now up to me to investigate her computer and figure out whether things were truly back to normal, or if something dangerous was still hiding in the background. 

---

## 🕵️‍♂️ The Investigation


### 💻 Using PowerShell to Investigate Sysmon Logs


I began by using PowerShell’s `Get-Content` command to read the contents of `SOPHIE.txt` on her desktop:  
```
PS C:\Users\Sophie\Desktop> get-content .\SOPHIE.txt
Check your bitcoin.
```
This matched exactly what my mother described.

**First Attempt:**

My first intuition was to open Powershell CLI and utilize `Get-WinEvent` along with `XPath` queries to filter events for investigation. So I opened powershell and typed out the following command:
```
Get-WinEvent -Path C:\Windows\System32\winevt\Logs\Microsoft-Windows-Sysmon%4Operational.evtx -filterXPath '*/System/EventID=11 and */EventData/Data[@Name="TargetFileName"]="C:\Users\Sophie\Desktop\SOPHIE.txt" | format-table *'
```
Explanation:

This command attempts to filter Sysmon logs (Sysmon/Operational) for Event ID 11, which corresponds to file creation events. It specifically looks for logs where the `TargetFileName` is `SOPHIE.txt` on the Desktop. The results would then be displayed in a table format where we can view all the relevant information.
Unfortunately, this yielded no events.

**Second Attempt:**

In my second attempt using Powershell CLI, I tried the following:
```
Get-WinEvent -Path C:\Windows\System32\Winevt\Logs\Microsoft-Windows-Sysmon%4Operational.evtx -filterXPath '*/System/EventID=1' | format-list * | Select-string -simplematch "SOPHIE"
```
Explanation:

Here I switched to searching for Event ID 1, which tracks process creation events. I then piped the output to `Select-String` to look for any process logs that mentioned `"SOPHIE"`.
This also did not return any results.


### 📂 Using Event Viewer


Since PowerShell queries weren’t giving me results, I switched to the Event Viewer GUI.
Navigating to `Applications and Services Logs → Microsoft → Windows → Sysmon → Operational`, I filtered for Event ID 1 (process creation) and then used the "Find" function to search for `SOPHIE.txt`.
This confirmed the text file was indeed created by Notepad.

<table>
  <tr>
    <td>
      <img width="1385" height="907" alt="Screenshot 2025-08-24 221349" src="https://github.com/user-attachments/assets/3a321623-b668-4cab-9be5-da13ab8660bc" />
    </td>
    <td>
      <img width="1222" height="723" alt="Screenshot 2025-08-24 221600" src="https://github.com/user-attachments/assets/7ad17f6f-823c-4e62-bed9-f28f770e72f2" />
    </td>
  </tr>
</table>


### 🔍 Investigating the installer


I then spoke with Sophie again, and she confirmed that all the problems began after running the antivirus “installer” she downloaded.

Checking her Microsoft Edge downloads, I located the suspicious installer file:

<img width="1437" height="770" alt="Screenshot 2025-08-24 225952" src="https://github.com/user-attachments/assets/61004967-f359-4385-9125-10adddc04b02" />

Strangely, there is another file called `decryptor.exe` here as well. Hmm, lets come back to that later...


### 📎 Strange `.dmp` extensions


While reviewing logs, I noticed many files with the `.dmp` extension being appended to her usual charity documents.

<img width="757" height="191" alt="Screenshot 2025-08-25 110127" src="https://github.com/user-attachments/assets/62253705-aefd-47b5-8a52-33531a69d615" />

After doing some research on this file extension, I learned that `.dmp` files are typically memory dump files generated when an application crashes. However, in this case, they appeared to be used by the malware to lock her documents, serving as the encryption extension for the ransomware.


### 🌐 Detecting Network Activity


Suspecting that the attacker may have reached out to an external IP, I looked at Sysmon Event ID 3 (network connections).
Filtering the logs around *2:14 PM on 01/08/2024* — the time the installer was executed — I discovered a connection logged at 2:15 PM

<img width="1917" height="912" alt="Screenshot 2025-08-24 225419" src="https://github.com/user-attachments/assets/1911f00d-9e45-4765-b9e6-5910165d8ec6" />

The threat actor’s IP address was revealed as `10.10.8.111`!


### 🛠️ The `decryptor`


I then asked my mother again about what happened, and she insisted the files had suddenly returned to normal while she was away.

This suggested that the attacker themselves may have restored the files. Checking Event Viewer logs, I confirmed that after the initial intrusion, the attacker logged in via RDP and executed a file called `decryptor.exe`. This seems to line up with the file that we saw earlier in Sophie's downloads.
Filtering for Event ID 1 and searching for the `decryptor` keyword revealed the process creation logs:

<img width="1878" height="818" alt="Screenshot 2025-08-24 230229" src="https://github.com/user-attachments/assets/cab80e7a-d130-4474-90f5-99e7497cd69b" />


### 📜 What Happened


After piecing together the events, here’s what I concluded:

1. Sophie downloaded the malware and ran it
2. The malware encrypted the files on the computer and showed a ransomware note.
3. After seeing the ransom note, Sophie came to me for help
4. While she was away, an intruder logged into the machine via RDP
5. Realizing the victim was a charity organization, the intruder decrypted the files using the newly downloaded `decryptor.exe` file. 
6. After restoring all her files, the intruder left a note telling Sophie to check her bitcoin.

Later, Sophie received a call from someone in Finance, who reported that a large amount of Bitcoin had been added to the charity’s account.

It seems that, strangely enough, the attacker decided to give back — at least in this case.

---


## 🎯 Learning outcomes:


- Learned how to use *Sysmon* logs effectively (Event ID 1 - Process Creation, Event ID 3 - Network Connections, Event ID 11 - File Creation) to reconstruct an attacker’s timeline.
- Practiced `PowerShell` log analysis with `Get-WinEvent` and `XPath` queries, and understood when to pivot to the Event Viewer GUI for deeper inspection.
- Identified how ransomware can leverage file extension manipulation (e.g., `.dmp`) to simulate or enforce encryption of user files.
- Discovered evidence of attacker persistence and remote access (RDP login) by correlating timestamps with Sysmon event logs.
- Strengthened skills in incident response investigation workflow: verifying user-reported symptoms, correlating logs, identifying Indicators of Compromise (IOCs), and determining attacker intent.
- Reinforced the importance of timeline analysis — aligning user reports, process creation, file modification, and network connections to piece together the attack narrative.
