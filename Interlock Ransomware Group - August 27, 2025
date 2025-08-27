# Threat Report: Interlock Ransomware Group (Nefarious Mantis)

This report summarizes the Interlock ransomware group, their targets, attack methods, and actionable defense recommendations.

---

## 🕵️ Who is Interlock?

The **Interlock ransomware group** (also called *Nefarious Mantis*) is a financially motivated and opportunistic threat actor first observed in **September 2024**.  

- Operates as a **closed group** (not RaaS).  
- Conducts **double extortion campaigns**: data theft → encryption → threat to leak on their site **“Worldwide Secrets Blog.”**  
- CISA and FBI issued warnings in **2025** due to increased activity and upgraded malware.  
- May be a **spin-off of Rhysida ransomware**.  

> ⚠ **Key Takeaway:** Interlock combines social engineering and living-off-the-land techniques with strong extortion pressure.

---

## 🎯 Targeting

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

## 🔓 Attack Methods

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

## 🛠 Recommended Defenses

### Employee Training
- Regular awareness on phishing, fake updates, and unusual prompts.  

### Prevent Initial Access
- DNS filtering & web firewalls to block malicious domains.  
- Block tunneling tools (like **TryCloudflare**) unless operationally required.  

### Vulnerability Management
- Patch OS, apps, and firmware consistently.  

### Network Segmentation
- Segment networks to reduce lateral movement.  

### Identity & Access Management
- Enforce **MFA** for email, VPN, and critical accounts.  
- Apply strong ICAM policies.  

### Endpoint Security
- Deploy **EDR platforms** (e.g., Arctic Wolf® Aurora™).  

### Incident Response Planning
- Maintain and regularly test an IR plan.  
- Have IR team or external partners on standby.  

### Continuous Monitoring
- Watch for **IOCs**:
