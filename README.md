
# Lab 01 — Splunk SIEM + Sysmon + Active Directory Attack Detection

> **Domain:** redblue / redblue.local
> **Network:** 192.168.10.0/24 — VirtualBox NAT Network
> **Hardware:** HP ENVY x360 i5-8250U 16GB RAM
> **Author:** Virginie Solomon-Bonhomme
> **Date:** May 2026
> **Status:** Complete

---

## Table of Contents

1. [What I Built](#what-i-built)
2. [My Virtual Machines](#my-virtual-machines)
3. [What I Installed and Configured](#what-i-installed-and-configured)
4. [The Attacks I Ran](#the-attacks-i-ran)
5. [What I Found in Splunk](#what-i-found-in-splunk)
6. [The Detection I Built](#the-detection-i-built)
7. [The Problem I Solved](#the-problem-i-solved)
8. [MITRE ATT&CK Coverage](#mitre-attck-coverage)
9. [What I Learned](#what-i-learned)
10. [Portfolio Evidence](#portfolio-evidence)

---

## What I Built

I built a four-VM cybersecurity home lab from scratch on my personal HP ENVY x360 
laptop running an i5-8250U processor with 16GB of RAM. I used VirtualBox to create 
an isolated NAT Network at 192.168.10.0/24 and configured a Windows Active Directory 
domain called redblue running at redblue.local. Every VM was built, configured, and 
hardened by me with no pre-built images or guided scripts.

<img width="694" height="500" alt="RedBlue_Diagram" src="https://github.com/user-attachments/assets/71e979e5-af38-4b37-8704-b15e8e073fb5" />

<img width="1096" height="937" alt="01-vm-inventory" src="https://github.com/user-attachments/assets/3dd24c0e-8ab5-4c53-924b-3d89f3485de0" />

*VirtualBox showing all four VMs — ADDC01, Target-PC, Splunk, and Kali Linux*

---

## My Virtual Machines

| VM | OS | IP | Role |
|---|---|---|---|
| Splunk | Ubuntu Server 22.04 | 192.168.10.10 | SIEM |
| ADDC01 | Windows Server 2022 | 192.168.10.7 | Domain Controller |
| Target-PC | Windows 10 | 192.168.10.100 | Victim Endpoint |
| Kali Linux | Kali 2026.1 | 192.168.10.250 | Attacker (deleted after use) |

### Splunk — 192.168.10.10

I built a Splunk SIEM server on Ubuntu Server 22.04. I installed Splunk Enterprise, 
configured UFW firewall rules restricting access to the lab subnet only, and set up 
the receiving port on 9997 to accept log forwarding from my endpoints.

### ADDC01 — 192.168.10.7

I built a Windows Server 2022 Domain Controller. I installed Active Directory Domain 
Services, promoted it to a domain controller for redblue.local, configured DNS, 
installed the Splunk Universal Forwarder, and deployed Sysmon for enriched endpoint 
telemetry.

### Target-PC — 192.168.10.100

I built a Windows 10 workstation and domain-joined it to redblue.local. I installed 
the Splunk Universal Forwarder, deployed Sysmon, and installed Atomic Red Team for 
controlled attack simulations.

### Kali Linux — 192.168.10.250

I built a Kali Linux attacker VM and used it to run real credential attacks against 
my domain. I deleted it after capturing all evidence to recover disk space.

---

## What I Installed and Configured

### Splunk Data Pipeline

I configured the Universal Forwarder to ship four log sources from each Windows 
endpoint into an index called **endpoint**:

I confirmed both hosts were sending data 
*Splunk confirming ADDC01 (8,933 events) and target-pc (2,740 events) are both 
sending data*

<img width="1920" height="923" alt="02-splunk-both-hosts" src="https://github.com/user-attachments/assets/5ab2929c-ddd9-48b7-8a80-b6ecc78f7e60" />


*Sysmon telemetry confirmed — ADDC01 (4,978 events) and target-pc (2,177 events)*
<img width="1920" height="923" alt="03-sysmon-confirmed" src="https://github.com/user-attachments/assets/7d840986-ea9c-48e9-b36e-f8dd1cc348c5"/> 


---

## The Attacks I Ran

### Kali Brute Force — Crowbar

I first ran Crowbar with a password wordlist against the swilliams account over 
RDP on port 3389. No credentials were found.

*Crowbar attacking 192.168.10.100:3389 with password wordlist — no results*
<img width="483" height="446" alt="10-kali-crowbar-attack" src="https://github.com/user-attachments/assets/455ca19b-3b09-4238-8bc6-52dd61de9c65" />

### Kali Brute Force — Hydra (Successful)

I then ran Hydra against the same target using the same wordlist and successfully 
cracked the swilliams account.
<img width="479" height="501" alt="09-kali-hydra-success" src="https://github.com/user-attachments/assets/f4096613-098b-404a-87a2-e3530d9dabf8" />

**Result:** `swilliams : Passtheword2020`
*Hydra successfully cracking swilliams — password: Passtheword2020*

### Atomic Red Team — T1059.001 PowerShell

I ran Atomic Red Team T1059.001 on Target-PC to simulate PowerShell-based attack 
techniques including Mimikatz and BloodHound sub-tests. Windows Defender detected 
and blocked several sub-tests — which is realistic behavior in a hardened 
environment. Sysmon still logged the execution attempt with file hashes and 
timestamps.

```powershell
Invoke-AtomicTest T1059.001
```

*Atomic Red Team executing T1059.001 — multiple sub-tests running*
<img width="750" height="750" alt="atomicred" src="https://github.com/user-attachments/assets/944efea5-d481-45e5-a387-0b9e8723888c" />

---

## What I Found in Splunk

### Brute Force Evidence — 47 Events

After running the Kali brute force attack I searched Splunk and found 47 EventCode 
4625 failed logon events across five accounts — all targeting 
target-pc.redblue.local.

```splunk
index=endpoint EventCode=4625
| stats count by Account_Name, ComputerName
| where count > 5
| sort -count
```

| Account | Count |
|---|---|
| (blank) | 25 |
| TARGET-PC$ | 23 |
| swilliams | 23 |
| Administrator | 12 |
| administrator | 7 |


### Raw Event Analysis — Logon Type 3

I investigated the raw event data and confirmed Logon Type 3 — a network-based 
attack — on the swilliams account. This confirmed the attack came over the network 
from Kali.

*Raw EventCode 4625 showing swilliams, Logon Type 3, target-pc.redblue.local*
<img width="1917" height="848" alt="04-brute-force-evidence" src="https://github.com/user-attachments/assets/4a3bd3a0-f4ed-4b6f-9d7f-6d892a5444bf" />


### T1059.001 PowerShell Detected in Splunk

I found Sysmon logs showing T1059.001 PowerShell execution on Target-PC from my 
Atomic Red Team test. 

```splunk
index=endpoint sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
earliest="05/15/2026:19:00:00" latest="05/15/2026:23:59:00"
technique_id=T1059.001
| table _time, host, technique_id, technique_name
```


*Sysmon logging T1059.001 PowerShell execution with MD5 and SHA256 hashes*
<img width="750" height="750" alt="atomicred2" src="https://github.com/user-attachments/assets/caa9c904-9fc5-4e12-aee1-29127b93dcf3" />


### T1003 Credential Dumping on Domain Controller


```splunk
index=endpoint sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
technique_id=T1003
| table _time, host, technique_id, technique_name
| sort -_time
```

*Sysmon T1003 Credential Dumping on ADDC01 — targeting lsass.exe*
<img width="1920" height="923" alt="14-splunk-T1003-lsass-full-access" src="https://github.com/user-attachments/assets/5594d4ed-d649-4ce1-9f67-869b20bf8f6c" />



---

## The Detection I Built

I built and saved **DET-002 — Brute Force Failed Logons** as a live Splunk 
scheduled alert.

```splunk
index=endpoint EventCode=4625
| stats count by Account_Name, ComputerName
| where count > 5
| sort -count
```

| Setting | Value |
|---|---|
| Alert Name | DET-002 Brute Force Failed Logons |
| Schedule | Cron — every 5 minutes (`*/5 * * * *`) |
| Trigger Condition | Number of Results is greater than 0 |
| Action | Add to Triggered Alerts |
| Severity | Medium |
| Status | Enabled |

*DET-002 alert configuration — enabled, scheduled, trigger condition confirmed*

<img width="1920" height="923" alt="alert2" src="https://github.com/user-attachments/assets/8a239e27-32c5-4c1a-9b6c-ea6d19355f98" />

<img width="1920" height="923" alt="alert1" src="https://github.com/user-attachments/assets/871dcbf4-ef6b-46ba-a83b-5bdf1147e813" />

---

## The Problem I Solved

During the lab my HP ENVY C: drive dropped to 1.75 GB free because the Kali Linux 
VM disk image consumed most of my available storage.

I made the deliberate decision to **complete the attack and capture all evidence in 
Splunk before taking any action on the storage issue.** Once I confirmed all attack 
evidence was indexed I deleted the Kali VM and recovered 46GB of disk space.

| State | Free Space |
|---|---|
| During Kali attack | 1.75 GB free |
| After Kali deleted | 63.8 GB free |



*C: drive at 1.75 GB free — critically low during Kali attack*

<img width="493" height="379" alt="LL-01-disk-space-critical" src="https://github.com/user-attachments/assets/9dabf7cc-33f9-47d3-aa86-a31f9bdd1582" />



*C: drive at 63.8 GB free — recovered after Kali VM deletion*
<img width="1381" height="714" alt="Screenshot 2026-05-17 122303" src="https://github.com/user-attachments/assets/805e4a0b-5504-4f4b-b05a-307c81b0fd52" />

> **Decision:** Evidence collection takes priority over storage management. 
> The evidence is what the lab exists to produce.

---

## MITRE ATT&CK Coverage

| Technique | Name | Tool Used | Detected in Splunk |
|---|---|---|---|
| T1110 | Brute Force | Kali — Hydra | ✅ 47 EventCode 4625 events |
| T1059.001 | PowerShell Execution | Atomic Red Team | ✅ Sysmon EID 7 with file hashes |
| T1003 | Credential Dumping | Atomic Red Team | ✅ Sysmon EID 10 — GrantedAccess 0x1fffff on lsass.exe |

---

## What I Learned

**Splunk index discovery.** My data was in an index called `endpoint` not `sysmon`. 
I troubleshot this by running `index=* | stats count by index` to discover what 
indexes existed. All 17,000+ events were in the correct location — I just needed 
to find them.

**Brute force has a signature.** A successful brute force attack generates many 
EventCode 4625 events clustered in a short time window from a single source 
against multiple accounts. Recognizing that pattern and building an automated 
detection rule to catch it is the core of SOC analyst work.

**Disk space is a real operational constraint.** Planning resource allocation 
before running storage-intensive tools — and knowing when to prioritize evidence 
collection over cleanup — are skills that transfer directly to production 
environments.

---

## Portfolio Evidence

All screenshots located in `/screenshots/`

| File | Description |
|---|---|
| vm-inventory.png | VirtualBox all 4 VMs |
| splunk-both-hosts.png | Both hosts sending data to Splunk |
| sysmon-confirmed.png | 7,155 Sysmon events from both hosts |
| brute-force-evidence.png | 47 EventCode 4625 — 5 accounts attacked |
| raw-4625-event.png | Raw swilliams failed logon Logon Type 3 |
| lsass-T1003-event.png | T1003 Credential Dumping on ADDC01 |
| DET-002-alert-detail.png | DET-002 alert configuration |
| DET-002-alerts-list.png | DET-002 enabled and scheduled |
| kali-hydra-success.png | Hydra cracking swilliams — Passtheword2020 |
| kali-crowbar-attack.png | Crowbar attack with password wordlist |
| atomic-T1059-execution.png | Atomic Red Team T1059.001 execution output |
| splunk-T1059-raw-event.png | T1059.001 PowerShell in Splunk |
| lessons-learned/LL-01-disk-space-critical.png | Drive at 1.75 GB — critical |
| lessons-learned/LL-01-disk-space-after-cleanup.png | Drive at 63.8 GB — recovered |

---

*Document ID: LAB-01-SPLUNK-SYSMON-2026 | Author: Virginie Solomon-Bonhomme | 
Domain: redblue.local | Network: 192.168.10.0/24 | Date: May 2026*
