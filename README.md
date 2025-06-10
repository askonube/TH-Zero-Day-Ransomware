
# Zero-Day Ransomware (PwnCrypt)

## Overview

One of the most challenging attacks to defend against is the zero-day exploit. These attacks are difficult to prevent because they target previously unknown vulnerabilities in newly developed code created by software engineers. Unfortunately, security teams can typically only respond after threat actors have gained initial access. However, this risk can be mitigated by implementing robust application security measures, conducting regular penetration testing, and running bug bounty programs. This investigation presents findings on a scenario where a threat actor has already executed the initial breach, along with recommended steps to prevent further exploitation and minimize damage to the enterprise network and its resources.

---

## 1. Preparation

### Scenario:

A new ransomware strain named PwnCrypt has been reported in the news, leveraging a PowerShell-based payload to encrypt files on infected systems. The payload, using AES-256 encryption, targets specific directories such as the `C:\Users\Public\Desktop`, encrypting files and prepending a `.pwncrypt` extension to the original extension. For example, `hello.txt` becomes `hello.pwncrypt.txt` after being targeted with the ransomware. The CISO is concerned with the new ransomware strain being spread to the corporate network and wishes to investigate.

### Hypothesis:

Given the organization's relatively new security infrastructure and limited user awareness, there is a heightened risk of infection and spread within the environment. It is plausible that PwnCrypt may have already compromised one or more systems. Therefore, the investigation should focus on identifying indicators of compromise (IoCs) and assessing the effectiveness of current detection and response measures to contain any potential outbreaks.

## 2. Data Collection
  
### Action:

Gather relevant data from logs, network traffic, and endpoints.

Ensure the relevant tables contain recent logs:

```kql
- DeviceProcessEvents
- DeviceFileEvents
```

#### Initial Findings:

A search was performed within the MDE `DeviceFileEvents` table for any activities that involved running the malicious Powershell payload and prepending the file extension `pwncrypt` before the actual file extension on existing files. The first file that was created was the `pwncrypt.ps1` PowerShell script, followed by the `6429_CompanyFinancials_pwncrypt.ps1`, `8566_EmployeeRecords_pwncrypt.csv` and `4145_ProjectList_pwncrypt.csv` files. Several  `.lnk` files were created and appended to the specific files that were infected by the ransomware listed previously. For reference, the `.lnk` file extension refers to Windows shortcut files that link to other files, folders and applications on the system without needing to navigate to the actual location. It's possible that there may have been file extraction because a 7-zip file manager and 7-zip help file were also created with the `.lnk` file extension. 


```kql
let VMName = "win-vm-mde";
let specificTime = datetime(2025-03-31T07:46:16.8839143Z);
DeviceFileEvents
| where DeviceName == VMName
| where Timestamp between ((specificTime - 20m) .. (specificTime + 13h))
| where ActionType == "FileCreated"
| where FileName contains ".lnk" or FileName contains "pwncrypt" or FileName contains ".zip"
//| where InitiatingProcessCommandLine contains "EXPLORER.exe"
//| where InitiatingProcessParentFileName contains "userinit.exe"
| order by Timestamp desc
```
<img width="904" alt="Pasted image 20250401004012" src="https://github.com/user-attachments/assets/e00a23b5-6700-47d7-a422-f63401042bbc" />

---

## 3. Data Analysis

### Findings

Using the query below on the `DeviceProcessEvents` table, it was important to confirm that the new ransomware strain was associated with the specific indicators of compromise (IoCs) found on the logs. 


```kql
let VMName = "win-vm-mde";
let specificTime = datetime(2025-03-31T07:46:16.8839143Z);
DeviceProcessEvents
| where Timestamp between ((specificTime - 5m) .. (specificTime + 20m))
| where DeviceName == VMName
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName,FileSize, ProcessCommandLine, InitiatingProcessCommandLine
```
#### *IoC 1: File Modification*

Some files on the system were modified by having the `.pwncrypt` extension prepended to their original file extension `(e.g., 4145_ProjectList.csv -> 4145_ProjectList_pwncrypt.csv)`.
  - The newly created malicious files were also renamed, but there seemed to be no apparent modification in file size or the file name.

<img width="1184" alt="Pasted image 20250331232852" src="https://github.com/user-attachments/assets/660612c7-34bc-45b2-82a6-f704b2422227" />

#### *IoC 2: Process Creation*

There were two process creations that took place around the time the `pwncrypt` files were created. 
  1. `cmd.exe: "cmd.exe" /c powershell.exe -ExecutionPolicy Bypass -File C:\programdata\pwncrypt.ps1`
  2. `powershell.exe: powershell.exe  -ExecutionPolicy Bypass -File C:\programdata\pwncrypt.ps1`

<img width="1153" alt="Pasted image 20250331232808" src="https://github.com/user-attachments/assets/ee81115d-5002-4de2-8dad-37c991150988" />


Both `cmd.exe` and `powershell.exe` were used to run scripts that bypass the PowerShell execution policy, a common defense evasion technique allowing scripts to execute without restrictions or persistent configuration changes.


The ransomware executes via PowerShell, encrypting files within the host’s Desktop directory and leaving instructions for the victim to decrypt their files. Unlike typical ransom notes delivered as `.txt` or `.html` files, this strain uses a `.lnk` shortcut file named `__________decryption-instructions.lnk` that points directly to the ransom note. When clicked, this shortcut opens the instructions, which inform the victim to send bitcoin to a specified address to obtain the decryption key. This use of a shortcut file is an uncommon but straightforward method to ensure the ransom note is accessible on the victim's Desktop.

<img width="359" alt="Pasted image 20250331233343" src="https://github.com/user-attachments/assets/f246ac98-786c-413e-9e9d-6088cb412728" />

<img width="581" alt="Pasted image 20250331233724" src="https://github.com/user-attachments/assets/1667f076-0ea6-4fbc-8337-e303eb438f29" />

#### *IoC 3: Persistence*

The ransomware strain also created `.lnk` files `(e.g., pwncrypt.lnk)` stored at the path `C:\Users\ylavnu\AppData\Roaming\Microsoft\Windows\Recent\pwncrypt.lnk`. These shortcut files are designed to persist on the host machine across user logins, ensuring that related ransomware components can execute again even if some are removed during eradication. Upon user login, the process execution chain follows this sequence: `winlogon.exe → userinit.exe → explorer.exe → pwncrypt.lnk` (the created shortcut file).

<img width="498" alt="Pasted image 20250401001137" src="https://github.com/user-attachments/assets/026e8a34-34f9-4246-ae65-41c96b560ca0" />


#### *IoC 4: File Extraction*

After running the query on the `DeviceFileEvents` table to check for any `.zip` files, no results indicated that compressed files were created or accessed. Based on this, we can reasonably conclude that no file compression or extraction activity involving `.zip` archives occurred on the host machine.

## 4. Investigation

**Suspicious Activity Origin**: The VM `windows-target-1` was exposed to the public internet for several days, resulting in multiple failed login attempts from external IP addresses, indicating potential brute-force attack activity against this internet-facing host.

**Potential Brute-Froce Login Attempts**: Numerous failed login attempts from external IPs were observed targeting the exposed VM, consistent with brute-force techniques aimed at gaining unauthorized access (T1110: Brute Force). Despite these attempts, no successful brute-force login was detected for the legitimate account `labuser`.

**Risk of Initial Access and Lateral Movement**: If any brute-force attempts had succeeded, attackers could have gained initial access to the shared services environment, which includes critical infrastructure such as DNS, Domain Services, and DHCP. This access could facilitate lateral movement within the network to expand control (T1021: Remote Services).

**Legitimate Account Behaviour**: The account "labuser" successfully logged in twice via network logons in the past 30 days, with no failed attempts and all logins originating from expected IP addresses, confirming no malicious activity or compromise associated with this account.
    
### MITRE ATT&CK TTPs

1. **Tactic: Initial Access (TA0001)** 
    
    - **Technique: Brute Force (T1110)** Adversaries attempt to gain access by guessing credentials, often targeting systems without account lockout mechanisms. Logs from `DeviceLogonEvents` show multiple failed login attempts (ActionType == "LogonFailed") from external IPs (e.g., 45.135.232.96, 185.39.19.71) targeting "windows-target-1," consistent with brute-force behavior.

2. **Tactic: Credential Access (TA0006)** 
    
    - **Technique: Brute Force (T1110)** The repeated failed login attempts indicate attempts to acquire valid credentials through brute force.
        
        
3. **Tactic: Initial Access (TA0001)** 
    
    - **Technique: Exploit Public-Facing Application (T1190)** Adversaries may exploit vulnerabilities in internet-facing applications to gain initial access. The VM "windows-target-1," hosting critical services (DNS, DHCP, Domain Services), was exposed to the internet (IsInternetFacing == true until 2025-06-09T11:06:17.2711518Z), making it a potential target for exploitation. While no direct evidence of application-specific exploits (e.g., CVEs or anomalous service behavior) was found in the logs, the internet exposure of these services increases the risk of such attacks, particularly if unpatched or misconfigured.
  
4. **Tactic: Lateral Movement (TA0008)** 
    
    - **Technique: Remote Services (T1021)** Successful compromise of the exposed VM could enable attackers to move laterally through the shared services cluster.

---

## 5. Response

### Actions Taken
- Immediately restrict internet exposure by limiting or removing public internet-facing configuration of the VM `windows-target-1` unless absolutely necessary.

- Implement firewall rules or network security groups (NSGs), if operating in a cloud environment, to restrict inbound traffic to only trusted IP addresses or networks.
  
- Implement strong, unique passwords and enable multi-factor authentication (MFA) for all user accounts.

- Enable account lockout policies after a configurable number of failed login attempts to mitigate brute-force attacks.

- Continuously monitor login attempts and network traffic for abnormal patterns

- Utilise intrusion detection/prevention systems (IDS/IPS) and endpoint protection tools to detect and block malicious activity

- Apply the principle of least privilege for accounts and services to minimise potential damage from compromised credentials.

## 6. Improvement

### Prevention:
- **Reduce Internet Exposure**: Limit or eliminate direct internet-facing access to critical VMs such as windows-target-1. Use VPNs, jump servers, or Just-in-Time (JIT) access to securely control remote connectivity.
- **Implement Account Lockout Policies**: Configure account lockout thresholds to block accounts after a set number of failed login attempts.
- **Enforce Strong Authentication**: Require complex passwords and enable multi-factor authentication (MFA) for all user accounts, especially those with remote access privileges.
- **Least Privilege Access**: Apply the principle of least privilege to user accounts and service permissions to minimize risk if credentials are compromised.

### Threat Hunting:
-  Continuously analyze authentication logs for patterns of failed login attempts from external IPs to detect brute-force activity early.
- Investigate accounts with multiple failed attempts followed by successful logins to identify potential credential compromise.
- Regularly review and inventory VMs exposed to the internet. Prioritize threat hunting on these assets due to higher risk exposure.
- Hunt for unusual remote service usage or authentication events within the shared services cluster that may indicate lateral movement attempts.
- Integrate external threat intelligence feeds to identify known malicious IP addresses attempting access and proactively block them.
- Establish normal login and network behavior baselines for critical accounts like labuser to quickly spot anomalies.

---

## Conclusion

Brute-force attacks will continue to be a mainstay in the modern cyber threat landscape. The vast trove of exposed credentials and stolen password lists will arm threat actors for the foreseeable future. Implementing security measures such as account lockout policies, multi-factor authentication, complex passwords, and the principle of least privilege are currently considered the absolute baseline standards for protecting against threat actors. Adopting basic security hygiene is essential to prevent businesses of all sizes from falling victim to common, yet effective, attacks.


