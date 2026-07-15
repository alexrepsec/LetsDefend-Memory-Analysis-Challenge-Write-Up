# 🧠 Memory Analysis — LetsDefend Challenge Write-Up
 
[![LetsDefend](https://img.shields.io/badge/-LetsDefend-00A3E0?&style=for-the-badge&logo=data:image/png;base64,&logoColor=white)](https://letsdefend.io)
[![Volatility](https://img.shields.io/badge/-Volatility-4B275F?&style=for-the-badge&logoColor=white)](https://www.volatilityfoundation.org/)
[![Hashcat](https://img.shields.io/badge/-Hashcat-000000?&style=for-the-badge&logoColor=white)](https://hashcat.net/)
[![DFIR](https://img.shields.io/badge/-DFIR-FF0000?&style=for-the-badge&logoColor=white)]()
 
---
 
## 📋 Overview
 
A Windows endpoint was compromised and detected by an EDR/IDS solution. As the forensics analyst on the case, I was handed a full memory dump of the compromised host and tasked with investigating the incident end-to-end.
 
| Field | Details |
|-------|---------|
| **Platform** | LetsDefend (now part of HackTheBox) |
| **Category** | Digital Forensics & Incident Response (DFIR) |
| **Difficulty** | Medium |
| **File** | `MemoryDump.zip` · password: `infected` |
| **Date** | July 2026 |
 
---
 
## 🛠️ Tools Used
 
### Forensics & Analysis
![Volatility](https://img.shields.io/badge/-Volatility_2.6.1-4B275F?&style=for-the-badge&logoColor=white)
![pefile](https://img.shields.io/badge/-pefile_(Python)-3776AB?&style=for-the-badge&logo=python&logoColor=white)
![strings](https://img.shields.io/badge/-strings_(Linux)-E95420?&style=for-the-badge&logo=ubuntu&logoColor=white)
 
### Credential Cracking
![Hashcat](https://img.shields.io/badge/-Hashcat-000000?&style=for-the-badge&logoColor=white)
![John](https://img.shields.io/badge/-John_the_Ripper-CC0000?&style=for-the-badge&logoColor=white)
 
---
 
## 🎯 Skills Demonstrated
 
| Skill | Description |
|-------|-------------|
| Memory Forensics | Analyzed a 1.8GB Windows memory dump using Volatility 2.6.1 |
| Process Analysis | Detected lsass spoofing via process tree anomaly (child of explorer.exe) |
| Binary Inspection | Identified renamed malware using PE metadata (OriginalFilename) |
| Credential Extraction | Extracted NTLM hashes from memory via hashdump |
| Password Cracking | Cracked NTLM hash using hashcat with dictionary attack |
| MITRE ATT&CK Mapping | Mapped attacker TTPs to ATT&CK framework |
| Windows Internals | Applied knowledge of Windows process hierarchy to detect anomalies |
| Incident Response | Followed full DFIR workflow from acquisition to attacker attribution |
 
---
 
## 🔍 Investigation Walkthrough
 
### Step 1 — Profile Identification
 
```bash
vol.py -f dump.mem imageinfo
```
 
```
Suggested Profile(s): Win10x64_17134
Image date and time:  2022-07-26 18:16:32 UTC+0000
```
 
> ✅ **Q1 — Date of acquisition:** `2022-07-26`
 
---
 
### Step 2 — Process Tree Analysis
 
```bash
vol.py -f dump.mem --profile=Win10x64_17134 pstree
```
 
Identified a second `lsass.exe` instance (PID 7592) running as a **child of explorer.exe** — a clear anomaly. In a legitimate Windows system, `lsass.exe` always runs under `wininit.exe`.
 
```
wininit.exe (500)
└── lsass.exe (640)        ← LEGITIMATE
 
explorer.exe (3996)
└── lsass.exe (7592)       ← MALICIOUS ⚠️
    └── conhost.exe (7560)
```
 
> ✅ **Q2 — Suspicious process:** `lsass.exe`
 
---
 
### Step 3 — Malicious Binary Identification
 
Dumped the fake `lsass.exe` and inspected its PE metadata to reveal its true identity:
 
```bash
vol.py -f dump.mem --profile=Win10x64_17134 procdump -p 7592 -D ./
 
python3 -c "
import pefile
pe = pefile.PE('executable.7592.exe')
for entry in pe.FileInfo[0]:
    if hasattr(entry, 'StringTable'):
        for st in entry.StringTable:
            for k,v in st.entries.items():
                print(k.decode(), ':', v.decode())
"
```
 
```
OriginalFilename : winPEAS.exe
InternalName     : winPEAS.exe
ProductVersion   : 1.0.0.0
```
 
The attacker renamed **winPEAS** (Windows Privilege Escalation Awesome Scripts) as `lsass.exe` to blend in with legitimate system processes.
 
> ✅ **Q3 — Malicious tool:** `winPEAS.exe`
 
---
 
### Step 4 — Compromised Account Identification
 
```bash
vol.py -f dump.mem --profile=Win10x64_17134 envars | grep COMPUTERNAME
vol.py -f dump.mem --profile=Win10x64_17134 hashdump
```
 
```
COMPUTERNAME: MSEDGEWIN10
 
CyberJunkie:1003:...:d13b3c4d5c10f0ce85af1a40b0ef30ec:::
```
 
> ✅ **Q4 — Compromised account:** `MSEDGEWIN10/CyberJunkie`
 
---
 
### Step 5 — Password Cracking
 
```bash
echo "d13b3c4d5c10f0ce85af1a40b0ef30ec" > hash.txt
hashcat -m 1000 hash.txt rockyou.txt --force
```
 
```
d13b3c4d5c10f0ce85af1a40b0ef30ec:Password123
```
 
> ✅ **Q5 — Compromised password:** `Password123`
 
---
 
## 🏁 Results Summary
 
| # | Question | Answer |
|---|----------|--------|
| 1 | Date & time memory was acquired | `2022-07-26` |
| 2 | Suspicious process running on the system | `lsass.exe` |
| 3 | Malicious tool used by the attacker | `winPEAS.exe` |
| 4 | Compromised user account | `MSEDGEWIN10/CyberJunkie` |
| 5 | Compromised user password | `Password123` |
 
---
 
## 🧩 MITRE ATT&CK Mapping
 
| Technique ID | Name | Observed |
|-------------|------|----------|
| T1003.001 | OS Credential Dumping: LSASS Memory | winPEAS targeting lsass |
| T1036.005 | Masquerading: Match Legitimate Name | winPEAS renamed as lsass.exe |
| T1057 | Process Discovery | winPEAS enumerating processes |
| T1078 | Valid Accounts | CyberJunkie account compromised |
| T1059.003 | Command and Scripting: Windows CMD | cmd.exe used to run encoded commands |
 
---
 
## 💡 Key Takeaways
 
- **Process tree analysis** is a fast and effective way to spot malicious processes masquerading as legitimate ones
- **PE metadata** (OriginalFilename) survives renaming and can unmask malware even when the file has been renamed
- **WDigest enabled** in memory means plaintext credentials may be recoverable — organizations should disable it
- **winPEAS** is a well-known post-exploitation enumeration tool — its presence indicates the attacker was already inside and escalating
---
 
*Write-up by [Alex D-L-C](https://github.com/alexrepsec) · [LinkedIn](https://www.linkedin.com/in/alexander-zayas/)*
