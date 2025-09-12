# 🕷️ ItsyBitsy

## 📖 Overview

During SOC monitoring, analyst John observed an alert on an IDS solution indicating potential C2 communication from a user named Browne in the HR department. A suspicious file containing the pattern `THM:{ ________ }` was accessed.

To investigate, a week’s worth of HTTP connection logs were pulled and ingested into the `connection_logs` index in Kibana.

The objective of this room is to analyze the logs, identify the user’s activity, and uncover the accessed file.

## 🛠️ Tools Used

- ELK Stack (Kibana)

---

## 📝 Tasks

### How many events were returned for the month of March 2022?

We first need to set the time filter to look at the month of March in 2022. 

[screenshot]

After setting it, we see that there are 1482 events

### What is the IP associated with the suspected user in the logs?

[screenshot]

By looking at the `source_ip` field in the left field pane, we can see where all the traffic is coming from. The suspected user Browne's IP is `192[.]166[.]65[.]54`

### The user’s machine used a legit windows binary to download a file from the C2 server. What is the name of the binary?

After setting the source_ip filter to the suspected user's IP, we can see we received 2 hits. Then, I proceeded to add various columns to our results, making it easier to get a better glance at the events that happened.

[screenshot]

We can see that the user used `bitsadmin` to download the file from the C2 server. Upon doing some research, it looks like `bitsadmin` is a command-line tool in Windows for managing Background Intelligent Transfer Service (BITS) jobs, which are used to download or upload files, often in the background. This is now a deprecated tool.  

### The infected machine connected with a famous filesharing site in this period, which also acts as a C2 server used by the malware authors to communicate. What is the name of the filesharing site?

Using the above screenshot, we know that the filesharing site is `pastebin[.]com`, with the full URL being `pastebin[.]com/yTg0Ah6a`.

### A file was accessed on the filesharing site. What is the name of the file accessed?

Upon going to the URL, we can see that the file `secret.txt` was accessed with the secret code being `THM{SECRET_CODE}`. Note that since we know simply accessing the `pastebin` URL will not cause any malicious actions, we were able to access the URL without taking any extra precautions such as using VM.

---

### 📚 Lessons Learned

- legitimate tools like BITSAdmin can be abused for malicious purposes
- common services like Pastebin may act as C2 infrastructure
- Monitoring logs in ELK/Kibana helps uncover malicious behaviour quickly