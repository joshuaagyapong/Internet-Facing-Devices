

In this project, we simulate a real-world **threat hunting investigation** where critical infrastructure systems (DNS, DHCP, Domain Controllers) were unintentionally exposed to the public internet, resulting in **brute-force login attempts**.
# 🕵️‍♂️ Threat Hunting Exercise: Detecting Exposed VMs and Brute-Force Logins

_**Inception State:**_ Organization had no external access controls or public exposure monitoring.
This project documents a practical threat hunting exercise focused on detecting virtual machines (VMs) exposed to the internet and identifying brute-force login attempts. It includes hypothesis formulation, data collection and analysis, investigation steps, response strategy, and lessons learned. Screenshots of results are included in the attached PDF.

_**Completion State:**_ Threat exposure is validated, brute-force attempts are analyzed, and actionable recommendations are delivered based on hunt findings.
---

## 📌 1. Preparation

**Goal:** Define the scope and hypothesis of the hunt.

During routine maintenance, the security team was tasked with identifying any VMs in the shared services cluster (handling DNS, Domain Services, DHCP, etc.) that were mistakenly exposed to the public internet.

> **Hypothesis:** During the period of exposure, attackers may have brute-force logged into some VMs, especially older ones lacking account lockout mechanisms.

---

## 🛠️ Technology Utilized
- Microsoft Sentinel (SIEM)
- Kusto Query Language (KQL)
- MITRE ATT&CK Framework (Threat Modeling)
- NIST SP 800-61 (Incident Handling Guidelines)
## 📥 2. Data Collection

**Goal:** Gather relevant data for investigation.

I inspected logs to detect devices exposed to the internet and flagged any with excessive failed login attempts. 

**Sources Queried:**
- `DeviceNetworkEvents`
- `DeviceLogonEvents`

**Key Data Points:**
- Remote IP addresses
- Number of failed attempts
- Logon types
- Action types (success/failure)

---

## 📚 Table of Contents
## 🔍 3. Data Analysis

- [🎯 Hypothesis Development](#-hypothesis-development)
- [🧠 Defining Data Sources and Detection Strategy](#-defining-data-sources-and-detection-strategy)
- [🔍 Threat Hunt Execution](#-threat-hunt-execution)
- [📝 Findings and Observations](#-findings-and-observations)
- [🛠️ Recommendations and Remediation Planning](#-recommendations-and-remediation-planning)
- [🚀 Post-Hunt Reflections and Lessons Learned](#-post-hunt-reflections-and-lessons-learned)
**Goal:** Analyze collected data to validate the hypothesis.

I focused on identifying:
- Evidence of brute-force attempts (many failures followed by a success)
- Patterns of behavior on compromised VMs
- Timeline correlation with potential threat actor activity

---

## 🎯 Hypothesis Development
## 💻 Query Breakdown

We initiated the hunt by formulating a clear hypothesis:
### 🔎 Step 1: Find Publicly Exposed Devices

> **"Publicly exposed critical servers are actively targeted with brute-force login attempts, potentially leading to unauthorized access."**
```kusto
DeviceNetworkEvents
| where RemoteIPType == "Public"
| where InitiatingProcessAccountName != ""
| order by TimeGenerated
| project TimeGenerated, DeviceName, RemoteIP, RemotePort, InitiatingProcessAccountName, ActionType
```
<img width="1139" height="538" alt="image" src="https://github.com/user-attachments/assets/21552aa1-0a9e-4407-849d-ef589ff97f03" />

🔵 Assumptions:
- Lack of firewall protections.
- Absence of lockout policies.
- Critical assets (Domain Controllers, DNS Servers) exposed without proper segmentation.

> ✅ Our VM `windows-target-1` is intentionally exposed and detected in the logs.

---

## 🧠 Defining Data Sources and Detection Strategy
### 🔐 Step 2: Failed Logon Attempts

```kusto
DeviceLogonEvents
| where DeviceName == "windows-target-1"
| where LogonType has_any("Network", "Interactive", "RemoteInteractive", "Unlock")
| where ActionType == "LogonFailed"
| where isnotempty(RemoteIP)
| summarize Attempts = count() by ActionType, RemoteIP, DeviceName
| order by Attempts
```
<img width="1144" height="855" alt="image" src="https://github.com/user-attachments/assets/b7aa43aa-3095-4887-89de-2848e50d3986" />

**Top 5 IPs attempting logons:**
- 204.157.179.2  
- 45.150.128.246  
- 213.165.94.209  
- 66.179.188.75  
- 104.237.250.98

---

Identifying the right data was crucial to validate the hypothesis:
### ✅ Step 3: Check for Successful Logons from These IPs

**Primary Data Sources:**
- 🔐 Authentication Logs (Azure Sign-In Logs, Windows Event 4625/4624)
- 🌐 Firewall/NSG Flow Logs (Public Access Detection)
```kusto
let RemoteIPsInQuestion = dynamic(["204.157.179.2", "45.150.128.246", "213.165.94.209", "66.179.188.75", "104.237.250.98"]);
DeviceLogonEvents
| where LogonType has_any("Network", "Interactive", "RemoteInteractive", "Unlock")
| where ActionType == "LogonSuccess"
| where RemoteIP has_any(RemoteIPsInQuestion)
```
<img width="1114" height="405" alt="image" src="https://github.com/user-attachments/assets/1d433227-b9b1-4835-8f30-1683f164aa30" />

**Detection Techniques:**
- 🧩 Pattern matching brute-force login attempts.
- 🚨 Correlating successful logins post multiple failures.
- 🗺️ Mapping activities to MITRE ATT&CK:
  - **T1110**: Brute Force
  - **T1078**: Valid Accounts
> ✅ No successful logons from these IPs were found.

---

### 🛡️ Sample Detection Query (KQL)
### 👤 Step 4: Identify Successful Logons

```kql
SigninLogs
| where ResultType in ("50126", "50053") // Failed Logins
| summarize AttemptCount = count() by IPAddress, TargetUserName, bin(TimeGenerated, 1h)
| where AttemptCount > 10
| order by AttemptCount desc
```kusto
DeviceLogonEvents
| where DeviceName == "windows-target-1"
| where LogonType has_any("Network", "Interactive", "RemoteInteractive", "Unlock")
| where ActionType == "LogonSuccess"
| distinct AccountName
```
<img width="1179" height="467" alt="image" src="https://github.com/user-attachments/assets/cb1edef3-d0f4-479f-9eee-27b045236c6f" />

## 🔍 Threat Hunt Execution
> Valid system accounts: `umfd-0`, `umfd-1`, `dwm-1`

Using Microsoft Sentinel, a series of KQL queries were executed to:
---

- Detect 🚨 high-volume failed authentication attempts.
- Identify 🌎 external IPs targeting critical systems.
- Confirm any 🔑 successful logins.
### 🧭 Step 5: Check for Login Failures by Valid Accounts

Sample Threat Hunting Visualization:
<!-- Insert visualization image here when available -->
```kusto
DeviceLogonEvents
| where DeviceName == "windows-target-1"
| where LogonType has_any("Network", "Interactive", "RemoteInteractive", "Unlock")
| where ActionType == "LogonFailed"
| where AccountName in~ ("umfd-0", "umfd-1", "dwm-1")
```
<img width="1143" height="308" alt="image" src="https://github.com/user-attachments/assets/6300e6ab-7da1-4d4f-9d90-b8e8bb9fb6a4" />

## 📝 Findings and Observations
> No unusual failed attempts were found for valid system accounts.

- 🌍 Multiple external IPs detected with sustained brute-force attacks (~500 attempts/hour).
- 🔥 One external IP achieved successful authentication after numerous failures.
- 🖥️ Compromised system had Domain Admin privileges within internal infrastructure.
- ⏳ Password policies were weak (no lockout threshold).
---

## 🛠️ Recommendations and Remediation Planning
## 🧪 4. Investigation

### 🔒 Firewall Hardening
- Block public inbound access to critical infrastructure servers.
**Goal:** Deep-dive into any suspicious behavior.

### 🔑 Authentication Improvements
- Enforce Multi-Factor Authentication (MFA) for all administrative accounts.
- Apply account lockout policies after 5 failed attempts.
I correlated detected behaviors with known TTPs (Tactics, Techniques, and Procedures) from the MITRE ATT&CK framework.

### ⚡ Real-Time Alerting
- Build SIEM alert rules for abnormal login activities (e.g., >10 failures/hour).
---

### 🔍 MITRE ATT&CK Mapping

| TTP ID | Name | Description | Status |
|--------|------|-------------|--------|
| **T1595.002** | Active Scanning: Vulnerability Scanning | Scanning of exposed system | ✅ Confirmed |
| **T1110.001** | Brute Force: Password Guessing | Repeated failed logins | ✅ Confirmed |
| **T1078** | Valid Accounts | Attempted use of valid credentials | ⛔ Prevented |
| **T1046** | Network Service Scanning | Likely network service probing | ⚠️ Implied |

---

## 🚨 5. Response

**Goal:** Contain and mitigate any confirmed threats.

Although there was no breach, the following actions were recommended:
- Revoke internet access from misconfigured VM
- Implement account lockout policy
- Apply IP throttling and geo-blocking
- Strengthen alert rules for brute-force behaviours

---

### 🕵️ Forensic Analysis
- Investigate compromised systems for signs of lateral movement or persistence mechanisms.
## 📝 6. Documentation

### 🛡️ Exposure Monitoring
- Implement regular public IP exposure assessments (e.g., Shodan alerts, external scans).
**Goal:** Maintain thorough documentation of the process.

## 🚀 Post-Hunt Reflections and Lessons Learned
All hunting queries, findings, and mapped TTPs were documented. This operation is now part of our internal threat hunting knowledge base and will be used in future playbooks.

### 📈 Key Takeaways:
- Visibility gaps (e.g., missing network flow logs) delayed detection.
- Public exposure + poor authentication = Critical Risk Factor.
- Automation of brute-force detection workflows would reduce response time significantly.
---

## 🔁 7. Continuous Improvement

**Goal:** Refine the process for future hunts.

**Recommendations:**
- Use CSPM tools to auto-detect misconfigurations
- Audit firewall/NAT rules regularly
- Apply lockout and MFA policies to legacy systems
- Enhance SIEM alert rules with brute-force detection logic

---

## 💻 Technologies Used

- **Microsoft Sentinel (KQL)**
- **MITRE ATT&CK Framework**
- **Threat Intelligence Feeds**
- Internal log tables: `DeviceInfo`, `DeviceLogonEvents`

---

### 🔔 Next Steps:
- Build continuous monitoring pipelines for public exposure.
- Integrate MITRE ATT&CK threat modeling into incident handling runbooks.
## 📚 Key Takeaways

## 📊 Final Summary
- Temporary exposure can attract real threats
- Regular posture assessments prevent major incidents
- Hunting based on hypothesis + data provides actionable outcomes

This project highlights the importance of structured threat hunting and hypothesis-driven investigation techniques. It showcased a real-world approach to identifying, analyzing, and remediating potential security breaches resulting from misconfigurations.
