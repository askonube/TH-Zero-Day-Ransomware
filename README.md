
# Zero-Day Ransomware (PwnCrypt)

## Overview

One of the most challenging attacks to defend against is the zero-day exploit. These attacks are difficult to prevent because they target previously unknown vulnerabilities in newly developed code created by software engineers. Unfortunately, security teams can typically only respond after threat actors have gained initial access. However, this risk can be mitigated by implementing robust application security measures, conducting regular penetration testing, and running bug bounty programs. This investigation presents findings on a scenario where a threat actor has already executed the initial breach, along with recommended steps to prevent further exploitation and minimize damage to the enterprise network and its resources.

---

## 1. Preparation

### Scenario:

A new ransomware strain named PwnCrypt has been reported in the news, leveraging a PowerShell-based payload to encrypt files on infected systems. The payload, using AES-256 encryption, targets specific directories such as the C:\Users\Public\Desktop, encrypting files and prepending a `.pwncrypt` extension to the original extension. For example, `hello.txt` becomes `hello.pwncrypt.txt` after being targeted with the ransomware. The CISO is concerned with the new ransomware strain being spread to the corporate network and wishes to investigate.

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

A search was performed within the MDE `DeviceFileEvents` table for any activities that involved running the malicious Powershell payload and prepending the file extension 'pwncrypt' before the actual file extension on existing files. The first file that was created was the `pwncrypt.ps1` PowerShell script, followed by the `6429_CompanyFinancials_pwncrypt.ps1`, `8566_EmployeeRecords_pwncrypt.csv` and `4145_ProjectList_pwncrypt.csv` files. Several  `.lnk` files were created and appended to the specific files that were infected by the ransomware listed previously. For reference, the `.lnk` file extension refers to Windows shortcut files that link to other files, folders and applications on the system without needing to navigate to the actual location. It's possible that there may have been file extraction because a 7-zip file manager and 7-zip help file were also created with the `.lnk` file extension. 


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

Several bad actors have been discovered attempting to log into the target machine.
```kql
DeviceLogonEvents
| where DeviceName == "windows-target-1"
| where LogonType has_any("Network", "Interactive", "RemoteInteractive", "Unlock")
| where ActionType == "LogonFailed"
| where isnotempty(RemoteIP)
| summarize Attempts = count() by ActionType, DeviceName, RemoteIP
| order by Attempts
```

![image](https://github.com/user-attachments/assets/118cc71a-2bd2-422c-9011-1490e67f2d9c)

We then checked to see if the top 5 IP addresses that failed to login the most were able to successfully login.

```kql
let AttemptedIPs = dynamic(["45.135.232.96", "185.39.19.71", "109.205.213.154", "118.107.45.60", "194.180.49.127"]);
DeviceLogonEvents
| where DeviceName == "windows-target-1"
| where LogonType has_any("Network", "Interactive", "RemoteInteractive", "Unlock")
| where ActionType == "LogonSuccess"
| where RemoteIP has_any(AttemptedIPs)
```

![image](https://github.com/user-attachments/assets/86d5e234-e993-48a8-a84d-a5bf9d63dc7a)

The only successful remote/network logons in the past 30 days was for the `labuser` account (2 times).

```kql
DeviceLogonEvents
| where DeviceName == "windows-target-1"
| where LogonType == "Network"
| where ActionType == "LogonSuccess"
| where AccountName == "labuser"
```
![image](https://github.com/user-attachments/assets/48468c7b-e8d7-4907-9d34-ee756869c5d5)

There were zero (0) failed logons for the `labuser` account, indicating that a brute force attempt for this account didn't take place, and a one-time password guess is unlikely.

```kql
DeviceLogonEvents
| where DeviceName == "windows-target-1"
| where LogonType == "Network"
| where ActionType == "LogonFailed"
| where AccountName == "labuser"
```
![image](https://github.com/user-attachments/assets/c9c7a14d-2733-4aa5-97dd-f3de82c86078)

We checked all of the successful login IP addresses for the `labuser` account to see if any of them were unusual or from an unexpected location. The IP address corresponded to their accurate location and was deemed safe. 

```kql
DeviceLogonEvents
| where DeviceName == "windows-target-1"
| where LogonType == "Network"
| where ActionType == "LogonSuccess"
| where AccountName == "labuser"
| summarize LoginCount = count() by DeviceName, ActionType, AccountName, RemoteIP
```

![image](https://github.com/user-attachments/assets/a9d2fcbd-aa61-46e0-b58d-d6901906660e)


Though the device was exposed to the internet and clear brute force attempts took place, there's no evidence of any brute force success or unauthorised access from the legitimate account `labuser`. 


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


