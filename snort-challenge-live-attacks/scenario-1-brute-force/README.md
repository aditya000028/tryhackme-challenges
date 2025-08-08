# 🛡️ TryHackMe Scenario 1: Stopping a Brute Force Attack on J&Y Enterprise

## 📘 Overview

**J&Y Enterprise** is one of the top coffee retailers in the world. Known as a tech-driven coffee shop, it serves millions of coffee-loving IT specialists every day. The company recently developed a **super-secret recipe** stored in a **digital safe**. Unfortunately, attackers are after this recipe, and J&Y is struggling to protect its digital assets.

Last week, they faced **multiple attacks** and have now enlisted your help to improve their defenses. As of now, the system is under a **brute force attack**.

Let’s dive in and stop this attack.

---

## 🔍 Step 1: Observe the Traffic with Snort

We begin by using **Snort** to monitor and capture network traffic. Situated in our desktop folder, we run the command below

### Command:
`sudo snort -n 100 -l .`

### Explanation:
- `sudo`: Snort needs superuser (root) rights to sniff the traffic, so we run with superuser privileges.
- `snort`: Invoke the Snort IDS/IPS tool.
- `-n 100`: Capture and analyze 100 packets only.
- `-l .`: Save the log output to the current directory (.).

After running the command, we get the following output:
<img width="722" height="822" alt="image" src="https://github.com/user-attachments/assets/fee40a72-be0b-412b-afa9-ab3c4d2765d5" />

This command has generated a log file for us. We can now use a snort command to read the log file.

### Command:
`sudo snort -r snort.log.1754616620 -dv`

### Explanation:
- `-r snort.log.1754616620`: Specifies the file to read
- `-dv`: Multiple flags combined into one. The `v` specifies to read the file in verbose mode including header information, and the `d` specifies to display the data payload

## 🧠 Step 2: Analyze and Identify the Anomaly

By entering the above command, we can see the logs with all the generated details. We can see the timestamp, source & destination IP addresses and ports, the protocol being used (TCP), TTLs, and more. We also see the data payload, which we speciifed earlier with the `-d` flag.
After scrolling through them, we quickly see a packet that stands out:
```
WARNING: No preprocessors configured for policy 0.
08/08-01:30:20.460707 10.10.245.36:46622 -> 10.10.140.29:22
TCP TTL:64 TOS:0x0 ID:1725 IpLen:20 DgmLen:948 DF
***AP*** Seq: 0x439A901  Ack: 0xE4C3A1C0  Win: 0x1EB  TcpLen: 32
TCP Options (3) => NOP NOP TS: 1884575793 4119683211 
00 00 03 7C 0B 14 24 60 E4 C1 26 56 42 78 D6 F9  ...|..$`..&VBx..
B3 43 39 1B 95 A8 00 00 00 71 63 75 72 76 65 32  .C9......qcurve2
35 35 31 39 2D 73 68 61 32 35 36 40 6C 69 62 73  5519-sha256@libs
73 68 2E 6F 72 67 2C 65 63 64 68 2D 73 68 61 32  sh.org,ecdh-sha2
2D 6E 69 73 74 70 32 35 36 2C 65 63 64 68 2D 73  -nistp256,ecdh-s
68 61 32 2D 6E 69 73 74 70 33 38 34 2C 65 63 64  ha2-nistp384,ecd
68 2D 73 68 61 32 2D 6E 69 73 74 70 35 32 31 2C  h-sha2-nistp521,
64 69 66 66 69 65 2D 68 65 6C 6C 6D 61 6E 2D 67  diffie-hellman-g
72 6F 75 70 31 34 2D 73 68 61 31 00 00 01 8B 72  roup14-sha1....r
73 61 2D 73 68 61 32 2D 35 31 32 2D 63 65 72 74  sa-sha2-512-cert
2D 76 30 31 40 6F 70 65 6E 73 73 68 2E 63 6F 6D  -v01@openssh.com
2C 72 73 61 2D 73 68 61 32 2D 32 35 36 2D 63 65  ,rsa-sha2-256-ce
72 74 2D 76 30 31 40 6F 70 65 6E 73 73 68 2E 63  rt-v01@openssh.c
6F 6D 2C 73 73 68 2D 72 73 61 2D 63 65 72 74 2D  om,ssh-rsa-cert-
76 30 31 40 6F 70 65 6E 73 73 68 2E 63 6F 6D 2C  v01@openssh.com,
73 73 68 2D 64 73 73 2D 63 65 72 74 2D 76 30 31  ssh-dss-cert-v01
40 6F 70 65 6E 73 73 68 2E 63 6F 6D 2C 65 63 64  @openssh.com,ecd
73 61 2D 73 68 61 32 2D 6E 69 73 74 70 32 35 36  sa-sha2-nistp256
2D 63 65 72 74 2D 76 30 31 40 6F 70 65 6E 73 73  -cert-v01@openss
68 2E 63 6F 6D 2C 65 63 64 73 61 2D 73 68 61 32  h.com,ecdsa-sha2
2D 6E 69 73 74 70 33 38 34 2D 63 65 72 74 2D 76  -nistp384-cert-v
30 31 40 6F 70 65 6E 73 73 68 2E 63 6F 6D 2C 65  01@openssh.com,e
63 64 73 61 2D 73 68 61 32 2D 6E 69 73 74 70 35  cdsa-sha2-nistp5
32 31 2D 63 65 72 74 2D 76 30 31 40 6F 70 65 6E  21-cert-v01@open
73 73 68 2E 63 6F 6D 2C 73 73 68 2D 65 64 32 35  ssh.com,ssh-ed25
35 31 39 2D 63 65 72 74 2D 76 30 31 40 6F 70 65  519-cert-v01@ope
6E 73 73 68 2E 63 6F 6D 2C 65 63 64 73 61 2D 73  nssh.com,ecdsa-s
68 61 32 2D 6E 69 73 74 70 32 35 36 2C 65 63 64  ha2-nistp256,ecd
73 61 2D 73 68 61 32 2D 6E 69 73 74 70 33 38 34  sa-sha2-nistp384
2C 65 63 64 73 61 2D 73 68 61 32 2D 6E 69 73 74  ,ecdsa-sha2-nist
70 35 32 31 2C 72 73 61 2D 73 68 61 32 2D 35 31  p521,rsa-sha2-51
32 2C 72 73 61 2D 73 68 61 32 2D 32 35 36 2C 73  2,rsa-sha2-256,s
73 68 2D 72 73 61 2C 73 73 68 2D 64 73 73 2C 73  sh-rsa,ssh-dss,s
73 68 2D 65 64 32 35 35 31 39 00 00 00 55 61 65  sh-ed25519...Uae
73 31 32 38 2D 67 63 6D 40 6F 70 65 6E 73 73 68  s128-gcm@openssh
2E 63 6F 6D 2C 63 68 61 63 68 61 32 30 2D 70 6F  .com,chacha20-po
6C 79 31 33 30 35 40 6F 70 65 6E 73 73 68 2E 63  ly1305@openssh.c
6F 6D 2C 61 65 73 31 32 38 2D 63 74 72 2C 61 65  om,aes128-ctr,ae
73 31 39 32 2D 63 74 72 2C 61 65 73 32 35 36 2D  s192-ctr,aes256-
63 74 72 00 00 00 55 61 65 73 31 32 38 2D 67 63  ctr...Uaes128-gc
6D 40 6F 70 65 6E 73 73 68 2E 63 6F 6D 2C 63 68  m@openssh.com,ch
61 63 68 61 32 30 2D 70 6F 6C 79 31 33 30 35 40  acha20-poly1305@
6F 70 65 6E 73 73 68 2E 63 6F 6D 2C 61 65 73 31  openssh.com,aes1
32 38 2D 63 74 72 2C 61 65 73 31 39 32 2D 63 74  28-ctr,aes192-ct
72 2C 61 65 73 32 35 36 2D 63 74 72 00 00 00 42  r,aes256-ctr...B
68 6D 61 63 2D 73 68 61 32 2D 32 35 36 2D 65 74  hmac-sha2-256-et
6D 40 6F 70 65 6E 73 73 68 2E 63 6F 6D 2C 68 6D  m@openssh.com,hm
61 63 2D 73 68 61 32 2D 32 35 36 2C 68 6D 61 63  ac-sha2-256,hmac
2D 73 68 61 31 2C 68 6D 61 63 2D 73 68 61 31 2D  -sha1,hmac-sha1-
39 36 00 00 00 42 68 6D 61 63 2D 73 68 61 32 2D  96...Bhmac-sha2-
32 35 36 2D 65 74 6D 40 6F 70 65 6E 73 73 68 2E  256-etm@openssh.
63 6F 6D 2C 68 6D 61 63 2D 73 68 61 32 2D 32 35  com,hmac-sha2-25
36 2C 68 6D 61 63 2D 73 68 61 31 2C 68 6D 61 63  6,hmac-sha1,hmac
2D 73 68 61 31 2D 39 36 00 00 00 04 6E 6F 6E 65  -sha1-96....none
00 00 00 04 6E 6F 6E 65 00 00 00 00 00 00 00 00  ....none........
00 00 00 00 00 5A 26 C3 AA A2 01 72 CD 34 7F EA  .....Z&....r.4..
```

The data payload looks to include SSH key exchange methods, algorithms, cipher and more. It seems that the attacker is trying to start a SSH session by listing many different algorithms, and key exchange methods as part of the SSH handshake to determine maximum compatibility.
We notice that there are many more repeated attempts from the ip address of `10.10.245.36` using different ports to our ip address of `10.10.140.29` on port `22`. This is definitely brute-force!

## ✍️ Step 3: Write a Snort Rule

Now that we've identified the attacker's IP, we can write a custom Snort rule to detect this malicious activity. We can create a file called `local.rules` and write the following line

### Rule: 
`alert tcp 10.10.245.36 any <> 10.10.140.29 22 (msg: "Bad actor interaction on port 22!"; sid: 1000001; rev: 1;)`

Explanation:
- `alert`: This action will generate an alert when the rule is triggered.
- `tcp`: Protocol being monitored.
- `10.10.245.36 any`: Source IP and any source port.
- `<>`: Bidirectional communication.
- `10.10.140.29 22`: Destination IP and SSH port (22).
- `msg`: Custom message that will appear in alert logs.
- `sid`: Unique Snort ID.
- `rev`: Revision number of the rule.

We can then test this rule by using the following command:

### Command:
`sudo snort -c local.rules -T`

### Explanation:
- `-c local.rules`: Use the config/rules file local.rules
- `-T`: Test mode. Validates the configuration and rules without running Snort.

At the end of the ouput, you should see a message saying Snort has successfully validated the configuration

## 🚫 Step 4: Stop the Attack (Enable Packet Dropping)

Now let’s change our rule from `alert` to `drop` to actually block the traffic. Here is our updated rule:
### Rule
`drop tcp 10.10.245.36 any <> 10.10.140.29 22 (msg: "Bad actor interaction on port 22!"; sid: 1000001; rev: 2;)`
(Note that we incremented the rev so that it helps analysts update their rule history)

Finally, we can then run the following command to start snort in IPS mode:
### Command:
`sudo snort -c local.rules -Q --daq afpacket -i eth0:eth1 -A full`

### Explanation:
- `-c local.rules`: Use our custom rule file.
- `-Q`: Enable inline (IPS) mode.
- `--daq afpacket`: Use the afpacket Data Acquisition (DAQ) module for inline sniffing.
- `-i eth0:eth1`: Use the specified interfaces for sniffing (in-line). 
- `-A full`: Output full alert messages.

After running snort for a short time, we receive the following notification from the VM, meaning that we stopped the attack
<img width="376" height="118" alt="Screenshot 2025-08-07 174956" src="https://github.com/user-attachments/assets/22f39af0-820b-47c6-8e9d-5ece21cd8409" />

---

## ✅ Learning Outcomes
- Snort can be used both as an IDS (Intrusion Detection System) and IPS (Intrusion Prevention System).
- We learned how to:
  - Capture and analyze traffic using Snort logs.
  - Identify anomalies such as brute force attempts.
  - Write and test custom Snort rules to detect malicious traffic.
- Rule tuning and targeted blocking help reduce false positives while stopping real attacks.
- Knowing how to analyze logs and take proactive security action is critical in real-world SOC (Security Operations Center) roles.
