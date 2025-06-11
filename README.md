
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


- The PwnCrypt ransomware was executed on the compromised machine `win-vm-mde` using a PowerShell script named `pwncrypt.ps1`. The attacker ran the script with a command that bypassed PowerShell execution policies, allowing the ransomware to run without restrictions.

- Analysis of process command lines from `DeviceProcessEvents` logs confirmed the use of the `-ExecutionPolicy Bypass` flag, a known method to evade PowerShell restrictions without changing system-wide settings.

- The ransomware encrypted files in targeted directories such as `C:\Users\Public\Desktop`, applying AES-256 encryption and modifying file extensions by appending `.pwncrypt`. File modification events in `DeviceFileEvents` logs corroborate this encryption activity.

- To maintain persistence, the ransomware created shortcut files `(.lnk)` like `pwncrypt.lnk` in the user’s `Recent` folder. These shortcuts are automatically executed during user login via a process chain starting from `winlogon.exe` through `explorer.exe`.

- These shortcut files also serve as a masquerading technique, appearing as benign shortcuts `(e.g., __________decryption-instructions.lnk)` but delivering ransom instructions to the victim.

- The ransom note instructs victims to manually send bitcoin to a specified wallet address, indicating a manual command and control approach rather than automated network communications.

- No evidence of file compression or extraction (e.g., .zip files) was found, indicating the ransomware did not perform file archiving on the host.

### MITRE ATT&CK TTPs

1. **Tactic: Execution (TA0002)** 
    
    - **Technique: PowerShell (T1059.001)** Adversaries used PowerShell to execute the `pwncrypt.ps1` script, bypassing execution policies with the command `powershell.exe -ExecutionPolicy Bypass -File C:\programdata\pwncrypt.ps1`. This allowed the ransomware payload to run without restrictions, as observed in the `DeviceProcessEvents` logs showing `powershell.exe` and `cmd.exe` process creations.

2. **Tactic: Defence Evasion (TA0005)** 
    
    - **Technique: Modify Execution Policy (T1562.001)** The ransomware bypassed PowerShell execution restrictions using the `-ExecutionPolicy Bypass` flag, a common defence evasion technique to execute scripts without altering persistent system configurations, as seen in the process command lines in `DeviceProcessEvents`.
        
3. **Tactic: Defence Evasion (TA0005)**
    
    - **Technique: Masquerading (T1036)**  The ransomware creates `.lnk` files, such as `__________decryption-instructions.lnk`, which masquerade as benign shortcut files but serve as a delivery mechanism for the ransom note. This technique involves modifying the file system to create files that appear legitimate to users, increasing the likelihood that victims will interact with the ransom note. The use of `.lnk` files to point to malicious instructions is a form of masquerading to evade detection and user suspicion.
  
4. **Tactic: Impact (TA0040)**  
    
    - **Technique: Data Encrypted for Impact (T1486)**  The ransomware encrypted files in targeted directories (e.g., `C:\Users\Public\Desktop`) using AES-256 encryption, appending the `.pwncrypt` extension to affected files (e.g., `4145_ProjectList_pwncrypt.csv`). This was confirmed by file modification events in the `DeviceFileEvents` table.
  
5. **Tactic: Persistence (TA0003)** 
    
    - **Technique: Boot or Logon Autostart Execution (T1547.001)** The creation of `.lnk` files (e.g., `pwncrypt.lnk`) in the `C:\Users\ylavnu\AppData\Roaming\Microsoft\Windows\Recent\` directory ensures persistence. These shortcut files are executed upon user login through the chain `winlogon.exe → userinit.exe → explorer.exe → pwncrypt.lnk`, as observed in the process execution logs.
  
6. **Tactic: Persistence (TA0003)**
    
    - **Technique: Create or Modify System Process: Windows File System (T1543.003)**  The creation of `.lnk` shortcut files `(e.g., pwncrypt.lnk` in `C:\Users\ylavnu\AppData\Roaming\Microsoft\Windows\Recent\)` involves modifying the file system to ensure persistence. These shortcut files are crafted to execute ransomware components upon user login, effectively modifying the system’s file structure to maintain malicious functionality. This aligns with creating or modifying files to establish persistent execution mechanisms.
  
7.  **Tactic: Command and Control (TA0011)** 
    
    - **Technique: Non-Application Layer Protocol (T1095)** This technique covers communication over non-standard or non-application layer protocols, such as manual cryptocurrency transactions. The ransom note’s instruction to send bitcoin to a wallet address represents a manual, out-of-band C2 mechanism where the adversary receives payment and may provide a decryption key via an external channel (e.g., email or a dark web portal). This better reflects the ransomware’s operation, as it relies on victim-initiated contact rather than automated network-based C2.

---

## 5. Response

### Actions Taken

- Immediately disconnected the infected machine `(win-vm-mde)` from the network, including disabling internet access and any local network connections, to prevent lateral movement and further spread of the ransomware.

- Took disk images or snapshots of affected systems to preserve the current state for analysis and potential law enforcement collaboration. Also captured any volatile data for forensic investigation.

- Alerted internal stakeholders including IT, security, legal, communications, and executive leadership

- Removed or quarantined suspicious persistence artifacts such as `.lnk` shortcut files used by the ransomware to maintain foothold
  
- Ran full antivirus and endpoint detection scans on infected hosts to remove ransomware binaries and related malware components

- Validated that all persistence mechanisms are eradicated before restoring systems.

- Restored affected systems and data from secure, offline backups following a recovery plan.

- Provided user training to increase awareness of ransomware delivery methods and suspicious file types (e.g., `.lnk` files)

## 6. Improvement

### Prevention:
- **Strengthen Endpoint Protection**: Configure endpoint protection to alert on or block execution of unauthorized `.ps1` scripts and suspicious `.lnk` files.
- **Monitor and Investigate Persistence Mechanisms**: Monitor creation and execution of `.lnk` shortcut files, especially in user profile directories such as `AppData\Roaming\Microsoft\Windows\Recent\`.
- **Enhance Detection of File Modification**: Monitor file system events for mass file modifications, particularly addition of unusual extensions like `.pwncrypt`.
- **Backup and Recovery**: Follow the 3-2-1 rule to enable rapid restoration without paying ransom.
- **User Awareness and Training**:  Educate users on recognizing suspicious files (e.g., `.lnk` shortcuts) and phishing attempts to reduce initial infection risk.


### Threat Hunting:
- Hunt for execution of PowerShell scripts with bypass flags and suspicious command lines in process logs (DeviceProcessEvents).
- Search for creation and execution of `.lnk` files in user profile directories, especially those executed during login sequences.
- Look for mass file modifications, especially files with unusual extensions like `.pwncrypt`.
- Investigate unusual process chains involving `winlogon.exe`, `userinit.exe`, and `explorer.exe` launching unknown shortcuts or scripts.

---

## Conclusion

Uncovering a zero-day exploit followed by deploying ransomware puts many organisations in extremely difficult positions. Not only are they pressured to pay a hefty ransom, but they also scramble to find a solution to patch the exploit and possibly recover their encrypted data. Organisations that do not follow industry-standard security practices are bound to experience such incidents sooner or later. However, even organizations that lead in implementing best cybersecurity practices may still face formidable adversaries against whom they might lose.

The important thing to remember is to ensure all bases are covered: maintain continuous monitoring, regularly update security controls, follow an incident response playbook diligently, and keep leadership promptly informed of the ongoing situation.


