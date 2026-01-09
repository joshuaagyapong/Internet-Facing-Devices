
# 🕵️‍♂️ Threat Hunting Exercise: Detecting Exposed VMs and Brute-Force Logins

This project documents a practical threat hunting exercise focused on detecting virtual machines (VMs) exposed to the internet and identifying brute-force login attempts. It includes hypothesis formulation, data collection and analysis, investigation steps, response strategy, and lessons learned. Screenshots of results are included in the attached PDF.

---

## 📌 1. Preparation

**Goal:** Define the scope and hypothesis of the hunt.

During routine maintenance, the security team was tasked with identifying any VMs in the shared services cluster (handling DNS, Domain Services, DHCP, etc.) that were mistakenly exposed to the public internet.

> **Hypothesis:** During the period of exposure, attackers may have brute-force logged into some VMs, especially older ones lacking account lockout mechanisms.

---

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

## 🔍 3. Data Analysis

**Goal:** Analyze collected data to validate the hypothesis.

I focused on identifying:
- Evidence of brute-force attempts (many failures followed by a success)
- Patterns of behavior on compromised VMs
- Timeline correlation with potential threat actor activity

---

## 💻 Query Breakdown

### 🔎 Step 1: Find Publicly Exposed Devices

```kusto
DeviceNetworkEvents
| where RemoteIPType == "Public"
| where InitiatingProcessAccountName != ""
| order by TimeGenerated
| project TimeGenerated, DeviceName, RemoteIP, RemotePort, InitiatingProcessAccountName, ActionType
```
<img width="1139" height="538" alt="image" src="https://github.com/user-attachments/assets/21552aa1-0a9e-4407-849d-ef589ff97f03" />


> ✅ Our VM `windows-target-1` is intentionally exposed and detected in the logs.

---

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

### ✅ Step 3: Check for Successful Logons from These IPs

```kusto
let RemoteIPsInQuestion = dynamic(["204.157.179.2", "45.150.128.246", "213.165.94.209", "66.179.188.75", "104.237.250.98"]);
DeviceLogonEvents
| where LogonType has_any("Network", "Interactive", "RemoteInteractive", "Unlock")
| where ActionType == "LogonSuccess"
| where RemoteIP has_any(RemoteIPsInQuestion)
```
<img width="1114" height="405" alt="image" src="https://github.com/user-attachments/assets/1d433227-b9b1-4835-8f30-1683f164aa30" />

> ✅ No successful logons from these IPs were found.

---

### 👤 Step 4: Identify Successful Logons

```kusto
DeviceLogonEvents
| where DeviceName == "windows-target-1"
| where LogonType has_any("Network", "Interactive", "RemoteInteractive", "Unlock")
| where ActionType == "LogonSuccess"
| distinct AccountName
```
<img width="1179" height="467" alt="image" src="https://github.com/user-attachments/assets/cb1edef3-d0f4-479f-9eee-27b045236c6f" />

> Valid system accounts: `umfd-0`, `umfd-1`, `dwm-1`

---

### 🧭 Step 5: Check for Login Failures by Valid Accounts

```kusto
DeviceLogonEvents
| where DeviceName == "windows-target-1"
| where LogonType has_any("Network", "Interactive", "RemoteInteractive", "Unlock")
| where ActionType == "LogonFailed"
| where AccountName in~ ("umfd-0", "umfd-1", "dwm-1")
```
<img width="1143" height="308" alt="image" src="https://github.com/user-attachments/assets/6300e6ab-7da1-4d4f-9d90-b8e8bb9fb6a4" />

> No unusual failed attempts were found for valid system accounts.

---

## 🧪 4. Investigation

**Goal:** Deep-dive into any suspicious behavior.

I correlated detected behaviors with known TTPs (Tactics, Techniques, and Procedures) from the MITRE ATT&CK framework.

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

## 📝 6. Documentation

**Goal:** Maintain thorough documentation of the process.

All hunting queries, findings, and mapped TTPs were documented. This operation is now part of our internal threat hunting knowledge base and will be used in future playbooks.

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

## 📚 Key Takeaways

- Temporary exposure can attract real threats
- Regular posture assessments prevent major incidents
- Hunting based on hypothesis + data provides actionable outcomes

> 🧠 *This project was performed as part of hands-on blue team training and demonstrates practical detection, investigation, and response skills aligned with real-world threat hunting frameworks.*
