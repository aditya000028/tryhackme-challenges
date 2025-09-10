# TShark Challenge I: Teamwork

## 🕵️‍♂️ Overview

An alert was raised by the threat research team:  
_"The threat research team discovered a suspicious domain that could be a potential threat to the organization."_

My task was to analyze the provided `teamwork.pcap` file using **TShark**, extract key Indicators of Compromise (IOCs), and verify threat intelligence via **VirusTotal**.

This challenge tested my ability to use **packet analysis** to uncover malicious activity and to identify domains, IPs, and email addresses that could be leveraged by attackers.

---

## 🛠️ Tools Used

- **TShark** – command-line network traffic analyzer based off of Wireshark
- **VirusTotal** – domain/IP, file, and hash reputation lookup

---

## Tasks

### What is the full URL of the malicious/suspicious domain address?

```bash
tshark -r teamwork.pcap -T fields -e http.host -Y 'http' | awk NF | sort | uniq
```

Explanation:

- `-r teamwork.pcap` → specifies the PCAP file to read
- `-T fields` → tells TShark to print specific fields
- `-e http.host` → extracts the HTTP host header (the domain being contacted)
- `-Y 'http'` → applies a display filter to only include HTTP traffic
- `awk NF` → removes any empty lines
- `sort | uniq` → sorts the results and removes duplicates

This resulted in the following output:

```
toolbarqueries[.]google[.]com
www[.]paypal[.]com4uswebappsresetaccountrecovery[.]timeseaways[.]com
```

After running the second url through VirusTotal, we can see that this site is malicious:

<img width="1916" height="635" alt="image" src="https://github.com/user-attachments/assets/2d0062fd-217d-47d1-ba70-c95ac5e836d7" />

### Which known service was the domain trying to impersonate?

Paypal

### What is the IP address of the malicious domain?

We run the following command, similar to the earlier one but with an additional field for IP destinations::

```bash
tshark -r teamwork.pcap -T fields -e ip.dst -e http.host -Y 'http' | awk NF | sort -n | uniq
```

Explanation

- `-e ip.dst` → extracts the destination IP address for each packet
- `-e http.host` → extracts the HTTP host associated with the request

Combined, this allows us to map hostnames to their IP addresses

We get the following output:

```
184[.]154[.]127[.]226	www[.]paypal[.]com4uswebappsresetaccountrecovery[.]timeseaways[.]com
192[.]168[.]1[.]100
216[.]58[.]217[.]100	toolbarqueries[.]google[.]com
```

**Note**: I have defanged the outputs to avoid accidental clicks

### What is the email address that was used?

```bash
tshark -r teamwork.pcap -Y 'http and ip.dst == 184.154.127.226' -V | grep -E "\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}\b"
```

Explanation:

- `-Y 'http and ip.dst == 184.154.127.226'` → filters traffic to only include HTTP packets going to the malicious IP
- `-V` → prints the full verbose packet details
- `grep -E ...` → uses regex to extract email addresses from the verbose output

We get the following output:

```
    Form item: "user" = "johnny5alive@gmail.com"
        Value: johnny5alive@gmail.com
```

---

## 🎯 Conclusion

This challenge demonstrated the power of TShark for packet capture analysis. By combining command-line filtering with external threat intelligence (VirusTotal), I was able to identify:

- A malicious phishing domain impersonating PayPal
- The IP address hosting the malicious domain
- An email address used in the attack

These IOCs could be fed into detection and monitoring systems to strengthen defenses against future attacks.

It seems like we are not finished. The second part of the challenge, TShark Challenge II: Directory, is [here!](./README-part2.md)
