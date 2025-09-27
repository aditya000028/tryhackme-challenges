# TShark Challenge II: Directory

## Overview 🕵️‍♂️

A user stumbled upon an exposed file index: curiosity triggered an alert — and problems followed.  
My mission was to analyze the provided `directory-curiosity.pcap` using **TShark** and confirm whether the alert is a true positive by extracting key Indicators of Compromise (IOCs).

---

## Tasks

### What is the name of the malicious/suspicious domain?

We filter for DNS queries to see what domains the client tried to resolve. Since we only care about A records (IPv4 address queries), we refine the filter:

```bash
tshark -r directory-curiosity.pcap -T fields -e dns.qry.name -Y 'dns and dns.qry.type == 1' | sort | uniq
```

Explanation:

- `-r directory-curiosity.pcap` → read packets from the provided capture file.
- `-T fields` → only print specific fields instead of full packet details.
- `-e dns.qry.name` → extract queried DNS domain names.
- `-Y 'dns and dns.qry.type == 1'` → apply a display filter to show only DNS A record queries.
- `sort | uniq` → clean up the output to remove duplicates.

We see the following result, which contains a few different domains:

```
api.bing.com
iecvlist.microsoft.com
jx2-bavuong[.]com
ocsp.digicert.com
r20swj13mr.microsoft.com
www.bing.com
```

These domains seem to be trusted, ordinary domains except one which stands out: `jx2-bavuong[.]com`. We can verify this by using VirusTotal, which flagged it as malicious:

<img width="1916" height="697" alt="image" src="https://github.com/user-attachments/assets/3c0d05d9-bfc5-4bf6-8690-e99c402c4a52" />

**Note:** I have defanged the URL to avoid accidental clicks

### What is the total number of HTTP requests sent to the malicious domain?

```bash
tshark -r directory-curiosity.pcap -Y 'http.host=="jx2-bavuong[.]com"' | wc -l
```

Explanation:

- `-Y 'http.host=="jx2-bavuong[.]com"'` filter selects only packets where the HTTP Host header equals the malicious domain.
- `wc -l` counts the number of lines, i.e., the number of matching packets/requests.

We get the output of `14`

### What is the IP address associated with the malicious domain?

```bash
tshark -r directory-curiosity.pcap -Y 'http.host=="jx2-bavuong[.]com"' -T fields -e ip.dst -e http.host | head -n 1
```

Explanation:

- Extract both `ip.dst` (destination IP address) and `http.host` fields.
- The filter ensures only packets to the malicious domain are included.
- `head -n 1` trims the result to the first matching packet (so we don’t see duplicate entries).

We get the following output:

```
141[.]164[.]41[.]174	jx2-bavuong[.]com
```

### What is the server info of the suspicious domain?

To get the server info, we need to switch things up slightly. Lets look at the network traffic coming from the malicious domain. We can then see the server field and then sanitize the output.

```bash
tshark -r directory-curiosity.pcap -Y 'ip.src==141[.]164[.]41[.]174' -T fields -e http.server | awk NF | uniq
```

Explanation:

- `-Y 'ip.src==141[.]164[.]41[.]174'` filters for traffic originating from the malicious server.
- `-T fields -e http.server` extracts the `server` header from HTTP responses.
- `awk NF | uniq` removes blank lines and ensures only unique values are displayed.

This is what we get for the output:

```
Apache/2.2.11 (Win32) DAV/2 mod_ssl/2.2.11 OpenSSL/0.9.8i PHP/5.2.9
```

It seems like the threat actor is using quite a few outdated and vulnerable technologies: an outdated Apache version on Windows, outdated and vulnerable OpenSSL build, and an outdated and vulnerable PHP version. This is a weak and vulnerable web server!

### Follow the "first TCP stream" in "ASCII" and investigate the output carefully. What is the number of listed files?

```bash
tshark -r directory-curiosity.pcap -z follow,tcp,ascii,0 -q
```

Explanation:

- `-z follow,tcp,ascii,0` tells TShark to follow the first TCP stream (stream index 0) and display its contents in ASCII format.
- `-q` suppresses normal packet-by-packet output so only the stream contents are shown.

We get the following output:

<img width="1902" height="515" alt="Screenshot 2025-09-10 185712" src="https://github.com/user-attachments/assets/4675b8d4-5111-4fc3-a254-0d6235428d07" />

This allows us to reconstruct the HTTP conversation. Within the server’s response, we see an index page listing files inside `<a href>` tags.

There are 3 files listed.

### Export all HTTP traffic objects. What is the name of the downloaded executable file?

To export files from the capture file, we can run this command:

```bash
tshark -r directory-curiosity.pcap --export-objects http,. -q
```

Explanation:

- `--export-objects http,.` extracts all HTTP objects (files transmitted over HTTP) into the current directory

We can then use `ls` to list the files in our current directory to spot the malicious `vlauto.exe` file.

<img width="1682" height="147" alt="Screenshot 2025-09-10 202217" src="https://github.com/user-attachments/assets/629754e5-c9a3-41d4-bb16-491a4b1fd3fe" />

### What is the SHA256 value of the malicious file?

We can run the following command to generate a SHA256 hash value of the malicious file:

```bash
sha256sum vlauto.exe
```

We get the following output:

```
b4851333efaf399889456f78eac0fd532e9d8791b23a86a19402c1164aed20de  vlauto.exe
```

We can then follow this up by looking up the hash in resources like VirusTotal:

<img width="1904" height="905" alt="image" src="https://github.com/user-attachments/assets/a9fcac18-02ef-4bb7-8228-fab673452f38" />

This seems to be a trojan!

---

## 🔑 Lessons Learned

1. DNS and HTTP analysis are powerful for IOC extraction – malicious activity often begins with suspicious domains, easily traceable in PCAPs.
2. Outdated servers remain a major risk – the attacker’s Apache + PHP + OpenSSL stack was riddled with known vulnerabilities.
3. Exporting and hashing files is critical – confirming the SHA256 hash allows correlation with threat intelligence databases.
4. Automation saves time – one-liners with TShark, combined with UNIX tools like `sort`, `uniq`, and `wc`, streamline investigations.
