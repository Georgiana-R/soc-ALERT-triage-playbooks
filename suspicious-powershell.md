SOC-Alert-Triage-Playbooks/
# Suspicious PowerShell Execution – Alert Triage

## Objective  
Assess a SIEM-generated alert related to potentially suspicious PowerShell activity and determine whether the execution is malicious or benign.

---

## Alert Details

| Field        | Value        |
|--------------|-------------|
| Alert Name   | Suspicious PowerShell Command |
| Severity     | Medium      |
| Host         | LAB-WIN10   |
| User         | test.user   |

---

## Initial Triage

The following analysis steps were conducted:

- Reviewed PowerShell command-line arguments for signs of obfuscation, encoded payloads, or suspicious flags  
- Investigated the parent process to identify abnormal process relationships or potential abuse of legitimate binaries  
- Validated user context and activity to determine whether execution aligns with expected behavior  
- Checked for common malicious PowerShell patterns, including:
  - Use of `-EncodedCommand`  
  - Execution via `Invoke-Expression (IEX)`  
  - Downloading or executing remote content  
  - Hidden or non-interactive execution flags  

---

## Observed Command

```powershell
powershell.exe -EncodedCommand <base64_string>
```

---
## Finding

- Encoded PowerShell command detected, indicating potential obfuscation

---

## Investigation

The following actions were performed:

- Decoded the Base64-encoded PowerShell payload  
- Reviewed:
  - Network connections associated with the process  
  - Active and spawned processes  
  - File system activity  

**Result:**  
The decoded script was observed performing system enumeration activities.

---

## Analysis

- Use of encoded PowerShell suggests an attempt to evade detection  
- No legitimate business justification identified for this activity  
- Observed behavior is consistent with reconnaissance techniques  

**Conclusion:**  
Activity is likely malicious and warrants further investigation.

---

## Response Actions

- Terminated the suspicious PowerShell process  
- Isolated the affected host (lab environment)  
- Escalated the incident for deeper analysis  

---

## Red Team Perspective

**Common attacker techniques:**

- Obfuscating payloads using encoding to bypass security controls  
- Leveraging native system tools (Living off the Land) to avoid detection  

**Potential improvements to attacker tradecraft:**

- Implement AMSI bypass techniques  
- Blend malicious activity with legitimate administrative scripts  
- Randomize encoding and execution patterns to reduce detection  

---

## Detection Opportunities

- Monitor for PowerShell execution with encoded command arguments  
- Ensure detailed command-line logging is enabled  
- Alert on unusual or suspicious parent-child process relationships  

---

## Lessons Learned

- Encoded commands require thorough inspection and decoding  
- Contextual analysis is critical to differentiate false positives from true threats  
- Detection rules should balance coverage with alert fatigue

