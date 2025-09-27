# 📘 Scenario 2 – Reverse Shell Detection

## 🔎 Overview:

The story in this scenario continues from Scenario 1 — we've successfully blocked the brute-force attack, but now we need to inspect outbound traffic for any suspicious signs of data exfiltration or unauthorized access.

---

## 🧪 Step 1: Monitor and Capture Packets with Snort
We begin again by using **Snort** to monitor and capture network traffic. In our desktop folder, we run the command below

### Command:
```
sudo snort -n 100 -l .
```

### Explanation:
- `sudo`: Snort needs superuser (root) rights to sniff the traffic, so we run with superuser privileges.
- `snort`: Invoke the Snort IDS/IPS tool.
- `-n 100`: Capture 100 packets only.
- `-l .`: Save the log output to the current directory (.).

We can now use a snort command to read the newly generated log file.

### Command: 
```
sudo snort -r snort.log.1754627679 -dv
```

### Explanation:
- `-r snort.log.1754616620`: Specifies the file to read
- `-dv`: Multiple flags combined into one. The `v` specifies to read the file in verbose mode including header information, and the `d` specifies to display the data payload

## 🕵️ Step 2: Analyze and Identify the Anomaly
The above command shows us the timestamp, source & destination IP addresses and ports, the protocol being used (TCP), the TCP header, and more in the log. We also see the data payload, which we specified earlier with the `-d` flag.

We again start to see some suspicious packets:
```
08/08-04:34:40.281947 10.10.196.55:54138 -> 10.10.144.156:4444
TCP TTL:64 TOS:0x0 ID:32333 IpLen:20 DgmLen:134 DF
***AP*** Seq: 0x410617BA  Ack: 0xA0519B6  Win: 0x1EB  TcpLen: 32
TCP Options (3) => NOP NOP TS: 2358498724 1980666398 
1B 5D 30 3B 75 62 75 6E 74 75 40 69 70 2D 31 30  .]0;ubuntu@ip-10
2D 31 30 2D 31 39 36 2D 35 35 3A 20 7E 07 1B 5B  -10-196-55: ~..[
30 31 3B 33 32 6D 75 62 75 6E 74 75 40 69 70 2D  01;32mubuntu@ip-
31 30 2D 31 30 2D 31 39 36 2D 35 35 1B 5B 30 30  10-10-196-55.[00
6D 3A 1B 5B 30 31 3B 33 34 6D 7E 1B 5B 30 30 6D  m:.[01;34m~.[00m
24 20                                            $ 

...

WARNING: No preprocessors configured for policy 0.
08/08-04:34:40.281984 10.10.144.156:4444 -> 10.10.196.55:54138
TCP TTL:64 TOS:0x0 ID:1353 IpLen:20 DgmLen:55 DF
***AP*** Seq: 0xA0519B6  Ack: 0x4106180C  Win: 0x1E9  TcpLen: 32
TCP Options (3) => NOP NOP TS: 1980672027 2358498724 
6C 73 0A                                         ls

...

08/08-04:34:40.361571 10.10.196.55:54138 -> 10.10.144.156:4444
TCP TTL:64 TOS:0x0 ID:32337 IpLen:20 DgmLen:119 DF
***AP*** Seq: 0x4106180F  Ack: 0xA0519B9  Win: 0x1EB  TcpLen: 32
TCP Options (3) => NOP NOP TS: 2358504330 1980672028 
44 65 73 6B 74 6F 70 0A 44 6F 63 75 6D 65 6E 74  Desktop.Document
73 0A 44 6F 77 6E 6C 6F 61 64 73 0A 4D 75 73 69  s.Downloads.Musi
63 0A 50 69 63 74 75 72 65 73 0A 50 75 62 6C 69  c.Pictures.Publi
63 0A 54 65 6D 70 6C 61 74 65 73 0A 56 69 64 65  c.Templates.Vide
6F 73 0A                                         os.

```

From the first packet, it looks to be like a Linux command prompt in the data payload, indicating that the command prompt is being sent over the network to the attacker. The attacker has a reverse shell set up. 

The second packet indicates the `ls` command being sent from the attacker's machine to the victim, to get a sense of the current files and folders in the victim machine. The attacker has remote command execution. 

Finally, the third packet shows the response of the ls command issued by the attacker, travelling from the victim to the attackers machine. The attacker is able to perform post-exploitation activities such as data exfiltration. 

We now know the IP address of the attacker and the port being used, which is `10.10.144.156` and `4444` respectively. 

## ✍️ Step 3: Write a Snort Rule
We can create a Snort rule to detect this malicious activity. After creating and naming a file `local.rules`, we can enter the following line:

### Rule:
```
alert tcp 10.10.144.156 4444 <> 10.10.196.55 any (msg: "Threat actor interaction detected!"; sid: 1000001; rev: 1;)
```

### Explanation:
- `alert`: This action will generate an alert when the rule is triggered.
- `tcp`: Protocol being monitored.
- `10.10.144.156 4444`: Source IP and port 4444 (often used by Metasploit).
- `<>`: Bidirectional communication.
- `10.10.196.55 any`: Destination IP and any port.
- `msg`: Custom message that will appear in alert logs.
- `sid`: Unique Snort ID.
- `rev`: Revision number of the rule.

We can then test this rule by using the following command:

### Command:
```
sudo snort -c local.rules -T
```

### Explanation:
- `-c local.rules`: Use the config/rules file local.rules
- `-T`: Test mode. Validates the configuration and rules without running Snort.

At the end of the output, you should see a message saying Snort has successfully validated the configuration

## 🚫 Step 4: Stop the Attack (Enable Packet Dropping)

Now let’s change our rule from `alert` to `drop` to actually block the traffic. Here is our updated rule:

### Rule
```
drop tcp 10.10.144.156 4444 <> 10.10.196.55 any (msg: "Threat actor reverse shell packets dropped"; sid: 1000001; rev: 2;)
```

(Note that we incremented the rev so that it helps analysts update their rule history)

Finally, we can then run the following command to start snort in IPS mode:
### Command:
```
sudo snort -c local.rules -Q --daq afpacket -i eth0:eth1 -A full
```

### Explanation:
- `-c local.rules`: Use our custom rule file.
- `-Q`: Enable inline (IPS) mode.
- `--daq afpacket`: Use the afpacket Data Acquisition (DAQ) module for inline sniffing.
- `-i eth0:eth1`: Use the specified interfaces for sniffing (in-line). 
- `-A full`: Output full alert messages.

After running snort for a short time, we receive the following notification from the VM, meaning that we stopped the attack
<img width="371" height="116" alt="Screenshot 2025-08-07 221207" src="https://github.com/user-attachments/assets/66e0fb22-42de-4a7b-9843-557a9ba9c2a3" />

---

## 🎓 Learning outcomes
- Recognize Reverse Shells: We learned how to identify reverse shell activity through payload patterns like visible command prompts and command execution.
- Write Detection Rules: We crafted custom Snort rules to detect attacker behavior based on IP and port combinations.
- Enable Prevention Mode: We transitioned from detection to prevention using Snort’s IPS capabilities, allowing live blocking of malicious traffic.
- Improve Rule Management: We incremented rule revisions for traceability and rule evolution.
