# Benign

## Overview

During SOC monitoring, one of the client’s IDS solutions raised an alert indicating a potentially suspicious process execution from a host in the HR department. Analysis revealed the use of tools related to network information gathering and scheduled tasks, confirming the suspicion of compromise.

Due to limited resources, only process execution logs (Windows Event ID 4688) were collected and ingested into Splunk under the index `win_eventlogs` for further investigation.

The network is divided into three departments:

| IT | HR | Marketing |
|------|-------------|--------|
| James | Haroon | Bell |
| Moin | Chris | Amelia |
| Katrina | Diana | Deepak |

## Tools Used

- Splunk

---

## Tasks

### Imposter Alert: There seems to be an imposter account observed in the logs, what is the name of that user?

First, I checked the UserName field but did not notice anything unusual at first glance.

[screenshot]

To dig deeper, I pivoted on rare values of the UserName field:

[screenshot]

This revealed the imposter account `Amel1a`, which closely resembles the legitimate `Amelia`.

### Which user from the HR department was observed to be running scheduled tasks?

We use the following SPL query to filter for results:

```spl
index=win_eventlogs schtasks.exe
```

`schtasks.exe` allows an admin to schedule tasks on a Windows machine, so this seems like a good place to start. Reviewing the results, the `UserName` field showed that `Chris.fort` from HR executed this binary.

[screenshot]

### Which user from the HR department executed a system process (LOLBIN) to download a payload from a file-sharing host?

LOLBins are Living off Land Binaries. They are legitimate Windows binaries often used by malicious actors to evade detection

The threat actor has various tools to choose from to download this payload, so I had to think outside of the box. I ran the following query:

```spl
index=win_eventlogs CommandLine=*http* | where match(HostName, "^HR_[0-9]+$")
```

I assumed that the threat actor had to make an `http`(s) request to download this payload. I also know the structure of the `HostName` of the departments. For HR, I knew it would match the regex `^HR_[0-9]+$` since the host names are structured like `HR_01`, `HR_02`, `HR_03` and so on (in our case, they only went up to `HR_03`, but its good to be thorough!). After running this query, we get the following result:

[screenshot]

We can see that `haroon` executed the `certutil.exe` lolbin from the URL `hxxps[://]controlc[.]com/e4d11035` (defanged for security/safety)

---

## Lessons Learned

- Small deviations in usernames (e.g., `Amel1a` vs. `Amelia`) can indicate impersonation attempts
- Native Windows binaries such as `schtasks.exe` and `certutil.exe` can be abused by threat actors
- Using Splunk effectively requires creative filtering and pattern recognition (e.g., regex for host naming conventions).
