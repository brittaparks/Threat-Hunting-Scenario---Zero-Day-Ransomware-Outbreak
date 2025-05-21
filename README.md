# Threat-Hunting-Scenario---Zero-Day-Ransomware-Outbreak

## Scenario

A new ransomware strain named **PwnCrypt** has been reported in the news, leveraging a PowerShell-based payload to encrypt files on infected systems. The payload, using AES-256 encryption, targets specific directories such as `C:\Users\Public\Desktop`, encrypting files and prepending a `.pwncrypt` extension to the original extension. For example, `hello.txt` becomes `hello.pwncrypt.txt` after being targeted with the ransomware. The CISO is concerned with the new ransomware strain being spread to the corporate network and wishes to investigate.

The security program at the organization is still immature and lacks user training. It’s possible the newly discovered ransomware has made its way onto the corporate network.

---

## Timeline Summary and Findings

### Initial File Search

I ran a command to search for files containing the aforementioned extension, but nothing appeared. I removed the `"."` and just searched for the name of the outbreak.

```kql
DeviceFileEvents
| where DeviceName == "windows-target-1"
| where FileName contains "pwncrypt"
| order by Timestamp desc
```

<img width="1515" alt="image" src="https://github.com/user-attachments/assets/0ae8996f-7c5f-4a32-9f43-ed6b36b717c7">


Findings: I noticed several files were being renamed as indicated in press releases describing the ransomware.

### Process Investigation

I took one of the instances of a file being created, took the timestamp, and searched under DeviceProcessEvents for anything happening 3 minutes before and 3 minutes after.

```kql
let specificTime = datetime(2025-05-21T20:13:35.1538586Z);
DeviceProcessEvents
| where DeviceName == "windows-target-1"
| where Timestamp between ((specificTime - 3m) .. (specificTime + 3m))
| order by Timestamp desc
```
<img width="1515" alt="image" src="https://github.com/user-attachments/assets/a25588d9-a948-4c92-a2a0-513049b333d0">


Findings: Around the same time, a PowerShell script named pwncrypt.ps1 was executed. The script contained -ExecutionPolicy Bypass, which is often seen in malware or unauthorized script execution. The script was run as `SYSTEM`, indicating high-level privileges.

### Network Investigation – Ransomware Script Activity

I searched the `DeviceNetworkEvents` table with the term pwncrypt.ps1 to determine if there were any network connections explicitly involving the ransomware.

```kql
DeviceNetworkEvents
| where DeviceName == "windows-target-1"
| where InitiatingProcessFileName == "powershell.exe"
| where InitiatingProcessCommandLine contains "pwncrypt.ps1"
| project Timestamp, RemoteIP, RemotePort, InitiatingProcessCommandLine
| order by Timestamp desc
```
<img width="1515" alt="image" src="https://github.com/user-attachments/assets/bc4762ea-7f16-43d7-ba82-9508f1d46e3b">


Findings: The device had multiple occurrences of downloads of the pwncrypt.ps1 script from GitHub via PowerShell Invoke-WebRequest.

### Network Investigation – Lateral Movement Check

I searched the `DeviceNetworkEvents` table for network activity on the device windows-target-1 within a one-hour window before and after the execution timestamp of the pwncrypt.ps1 script to focus on possible lateral movement.

```kql
let specificTime = datetime(2025-05-21T20:13:35.1538586Z);
DeviceNetworkEvents
| where DeviceName == "windows-target-1"
| where Timestamp between ((specificTime - 1h) .. (specificTime + 1h))
| project Timestamp, RemoteIP, RemotePort, InitiatingProcessFileName, Protocol, ReportId
| sort by Timestamp asc
```
<img width="1515" alt="image" src="https://github.com/user-attachments/assets/e595ec50-7cdb-4b05-8c70-029c30ba7bad">


Findings: While there were many events, none appeared abnormal or indicative of suspicious lateral activity.

## Response Actions

-  Isolated the affected system

-  Terminated the PowerShell and pwncrypt.ps1 processes

-  Ran antivirus software

-  Checked for other compromised machines on the network
    
## MITRE ATT&CK Techniques

| Technique ID | Technique Name                                          |
|--------------|--------------------------------------------------------|
| T1053.005    | Scheduled Task/Job: Scheduled Task                     |
| T1059.001    | Command and Scripting Interpreter: PowerShell          |
| T1105        | Ingress Tool Transfer                                  |
| T1204.002    | User Execution: Malicious File                         |

## Recommendations

- Implement PowerShell logging via GPO or Sysmon to detect future script-based attacks.

- Block or monitor `Invoke-WebRequest` and outbound PowerShell access to GitHub and other code-sharing platforms.

- Implement EDR policies that alert on `-ExecutionPolicy Bypass` and `SYSTEM`-level PowerShell execution.

- Enable regular backups to protect against ransomware encryption.

---

### Analyst Contact

  Name: Britt Parks

  Contact: [linkedin.com/in/brittaparks](https://linkedin.com/in/brittaparks)

  Date: May 21, 2025
