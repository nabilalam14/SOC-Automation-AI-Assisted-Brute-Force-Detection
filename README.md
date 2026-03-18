# SOC-Automation-AI-Assisted-Brute-Force-Detection
Automated SOC workflow for detecting brute-force authentication attempts using Splunk, AI-assisted analysis, threat intelligence enrichment, and Slack alerting.
# 🛡 SOC Automation with AI  
**Splunk • n8n • OpenAI • Threat Intelligence • Slack**

## 📌 Project Overview

This project demonstrates an **automated Security Operations Center (SOC) workflow** that detects brute-force authentication attempts, enriches indicators of compromise (IOCs), and delivers **AI-assisted incident analysis** directly to Slack.

The purpose of this project is to explore how **SIEM detections, automation, threat intelligence, and AI** can be combined to reduce manual triage effort while preserving analyst judgment.

---

## 🔧 What This Project Builds

- Splunk alert for brute-force authentication attempts  
- n8n workflow for SOC automation  
- ChatGPT integration for incident analysis  
- AbuseIPDB threat intelligence enrichment  
- Slack notifications for real-time alerting  

---

## 🧠 Technical Architecture

```
Splunk Alert
↓
Webhook (n8n Trigger)
↓
OpenAI (SOC Incident Analysis Engine)
   └── AbuseIPDB API (IP Reputation Enrichment)
↓
Slack (SOC Alert Notification)
```
<img width="1114" height="469" alt="image" src="https://github.com/user-attachments/assets/f214c35a-9f35-4b17-81e1-93735773e09a" />

```
Detection Layer:
- Splunk Alert

Ingestion Layer:
- n8n Webhook

Decision Layer (AI Agent):
- OpenAI
   └── Tool: AbuseIPDB

Action Layer:
- Slack Notification
```
---

## 🔍 Detection Logic (Splunk)

### Use Case
Detect repeated **failed Windows logon attempts** indicative of brute-force behavior.

### SPL Query
```spl
index=nabil-project "eventcode=4625"
| stats count by _time, ComputerName, user, src_ip
| sort - count
```

### Alert Configuration
- Scheduled alert (cron-based)
- Trigger condition: **Number of results > 0**
- Action: Send results via **Webhook**

---

## 🔄 SOC Automation Workflow (n8n)

### Workflow Components

- **Webhook Trigger**
  - Receives alert payload from Splunk

- **Message a Model (OpenAI)**
  - Performs Tier 1 SOC-style analysis
  - Summarizes activity and impact
  - Maps behavior to MITRE ATT&CK
  - Assesses severity
  - Recommends next investigation steps

- **AbuseIPDB Enrichment**
  - Evaluates source IP reputation
  - Identifies known malicious infrastructure

- **Slack Notification**
  - Delivers structured SOC alerts

---

## 🤖 AI Model Prompting (Message a Model)

The OpenAI model is explicitly instructed to act as a **Tier 1 SOC analyst assistant**.

### System Prompt
```text
Act as a Tier 1 SOC analyst assistant.

When provided with a security alert or incident details, perform the following:
- Summarize what triggered the alert and which systems/users are affected
- Enrich indicators of compromise using available threat intelligence
- Map activity to MITRE ATT&CK tactics and techniques
- Assign an initial severity (Low, Medium, High, Critical)
- Recommend next investigation or containment actions
```

### User Prompt (Dynamic Context)
```text
Alert: {{ $json.body.search_name }}

Alert Details:
{{ JSON.stringify($json.body.result['_time','user','ComputerName']) }}

Source IP: {{ $json.body.result.src_ip }}
```

---

## 🧬 Threat Intelligence Enrichment

**Source:** AbuseIPDB  

**Purpose:**
- Validate malicious infrastructure
- Reduce false positives
- Provide additional analyst context

---

## 🧠 Design Decisions

This project was intentionally designed to mirror **real SOC operating constraints**:

- Scheduled alerts were chosen over real-time streaming to reduce SIEM overhead
- AI output is advisory only to avoid false-positive remediation
- Modular workflow design for maintainability
- Severity is driven by impact confirmation, not raw volume

---

## 🚨 False Positive Considerations

- Internal IP ranges may generate benign failures
- Single-user failures are lower risk
- Short bursts without follow-on activity are deprioritized
- No severity escalation without successful authentication

---

## 📌 Scope Clarification

### In Scope
- Brute-force detection
- Alert triage and enrichment
- Analyst decision support
- SOC workflow automation

### Out of Scope
- Automatic IP blocking
- Account disablement
- Remediation without analyst review

---

## 🎯 MITRE ATT&CK Mapping

| Tactic | Technique | Description |
|------|----------|------------|
| Credential Access | T1110 | Brute Force |
| Initial Access | T1078 | Valid Accounts (attempted) |

---

## 🚦 Severity Decision Logic

| Condition | Severity |
|---------|----------|
| Failed attempts only | Medium |
| External IP source | Increases risk |
| Multiple users targeted | Higher risk |
| Successful authentication | High |
| Privileged account involved | Critical |

---

## 📣 Example Slack Alert Output (Redacted)

```text
Alert: Brute-Force Authentication Detected
Severity: Medium
User: test-user
Host: WIN-CLIENT-01
Source IP: 185.xxx.xxx.16

Summary:
Multiple failed authentication attempts were detected from an external IP address
against a single user account. No successful logons were observed.

Recommended Actions:
- Monitor for successful authentication attempts
- Review account lockout policies
- Block IP if malicious behavior persists
```
## 🌐 Public IP Response
<img width="1383" height="619" alt="image" src="https://github.com/user-attachments/assets/7596558e-6a24-4ce9-aa93-10ccc8421aa8" />
## 🏠 Private IP Response 
<img width="1081" height="582" alt="Screenshot 2026-02-02 215558" src="https://github.com/user-attachments/assets/89aff289-8109-451a-b72a-edf9f50dcfdd" />



---

## 🧠 Lessons Learned

- Structured prompts improve AI reliability
- Enrichment before severity improves confidence
- Automation should support analysts, not replace them
- Context matters more than alert volume

---

## 🏭 Production Considerations

- Webhook authentication and validation
- Rate limiting for AI usage
- Secure secret management
- Case management integration
- Prompt logging and auditability

---

## 🚀 Future Enhancements

- VirusTotal or OTX enrichment
- Password spraying detection
- MFA fatigue detection
- Case management integration
- Conditional containment actions

---

## 👤 Author

**Nabil Alam**  
Cybersecurity | SOC | Automation  

GitHub: https://github.com/nabilalam14
