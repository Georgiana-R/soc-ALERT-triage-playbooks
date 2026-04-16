# Detection vs Evasion Notes

---

## Common Detection Methods

- Command-line logging (PowerShell Script Block Logging, Process Creation Events)
- SIEM correlation rules for suspicious execution patterns
- Endpoint Detection and Response (EDR) behavioral analysis
- Detection of encoded or obfuscated command execution
- Monitoring parent-child process relationships (e.g., `winword.exe → powershell.exe`)

---

## Common Evasion Techniques

- PowerShell encoding (e.g., `-EncodedCommand`)
- Script obfuscation (string manipulation, variable splitting, compression)
- Living-off-the-Land Binaries (LOLBins) to blend into legitimate activity
- Disabling or bypassing security controls (e.g., AMSI bypass techniques)
- Process injection and memory-based execution

---

## MITRE ATT&CK Mapping

| Technique | ID | Description |
|-----------|----|-------------|
| Command and Scripting Interpreter: PowerShell | T1059.001 | Execution of malicious commands via PowerShell |
| Obfuscated Files or Information | T1027 | Use of encoding or obfuscation to evade detection |
| System Information Discovery | T1082 | Enumeration of system details for reconnaissance |
| Process Injection | T1055 | Injection of code into legitimate processes |
| Signed Binary Proxy Execution (LOLBins) | T1218 | Abuse of trusted binaries to execute malicious code |

---

## SOC Insight → Red Team Perspective

From a SOC analyst perspective:
- Focus is on identifying anomalous behavior, suspicious execution chains, and encoded payloads  
- Detection relies on telemetry from endpoints, logs, and correlation across systems  
- Goal is early identification and containment of malicious activity  

From a red team perspective:
- Focus is on understanding detection logic and security gaps  
- Techniques are adapted to resemble legitimate administrative behavior  
- Objective is to remain undetected while achieving execution and persistence  

---

## Key Takeaway

- Detection engineering and adversary tradecraft are tightly linked  
- Understanding both sides improves investigation quality and detection coverage  
- Encoding and obfuscation remain high-signal indicators when combined with execution context  
