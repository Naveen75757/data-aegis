# Data-Aegis — AI Security Posture Management Gateway

Data-Aegis is an AI-native security middleware that protects enterprise data from being exposed through AI agents. As companies connect AI systems to their internal data stores, those agents can accidentally read and leak sensitive information — SSNs, AWS credentials, patient records, financial data. Data-Aegis sits between the AI agent and the enterprise data, intercepting every query, classifying sensitive fields, masking them before the AI reads anything, and generating a full security audit trail for every interaction.

Built to mirror the architecture of modern AI data security platforms, Data-Aegis demonstrates two complementary security layers working together — real-time middleware interception and continuous audit scanning — giving enterprises both prevention and detection in one system.

---

## The Problem

Enterprises are connecting AI agents to massive internal data stores. Those agents pull data to answer employee queries but they have no awareness of what's sensitive and what isn't. An AI agent asked to summarize recent customer support tickets might pull records containing SSNs, AWS access keys, or patient diagnoses and include that information directly in its response.

This is not a theoretical risk. It is happening right now across every industry as companies race to deploy AI without the security controls to match.

---

## How Data-Aegis Solves It

Data-Aegis runs as a standalone Flask API server. AI agents cannot access enterprise data directly — every query must go through the Data-Aegis middleware endpoint. The middleware intercepts the request, searches the data store, scans every record for sensitive fields, masks them using targeted redaction per data class, and returns only clean sanitized data to the AI agent.

The AI responds to the user without ever having seen the raw sensitive data. The exposure never happens.
AI Agent sends query

|

v

Data-Aegis API (localhost:5000)

|

v

Intent Analysis — is this query malicious?

|

v

Database Search — find relevant records

|

v

Sensitive Field Detection — PII, credentials, HIPAA, IAM, financial

|

v

Dynamic Masking — targeted redaction per data class

|

v

Incident Generation — MITRE ATT&CK tagged, SIEM-style alert

|

v

Clean Data returned to AI Agent

|

v

AI responds safely — sensitive data never exposed

---

## Two Security Layers

### Layer 1 — Continuous Audit Scanner

An autonomous agentic SOC monitoring loop that continuously processes enterprise CloudTrail log streams, detecting sensitive data that may have been accidentally captured in operational logs. The agent maintains stateful threat memory across monitoring cycles, escalating risk scores when the same regions or patterns appear repeatedly. Every finding is classified, MITRE ATT&CK tagged, and written to a persistent audit trail.

This layer catches what the middleware missed and provides the compliance audit record that regulators require.

### Layer 2 — Real-Time Data Middleware

The Flask API service that intercepts AI agent queries before database access. This is the prevention layer — stopping sensitive data from reaching the AI in the first place. Combined with Layer 1 which catches anything that slipped through, the two layers implement genuine defense in depth.

---

## Features

**True Middleware Architecture**
Data-Aegis runs as a completely independent server process. The AI agent makes real HTTP POST requests to the Data-Aegis API. It cannot access the database directly. This is not a simulation — it is actual middleware separation with real HTTP interception.

**LLM Contextual Classification**
Uses LLaMA 3.3 70B via Groq to classify log entries and database records semantically. Unlike regex-based detection, LLM classification understands context — it catches sensitive data even when it appears in unexpected formats or phrasing.

**Dynamic Masking Per Threat Class**
Each data class gets targeted redaction. PII fields get SSN, email, phone, and date of birth masked. Credential records get AWS access keys and secrets redacted. Healthcare records get diagnosis codes, prescriptions, and insurance IDs masked. The masking is surgical — safe fields pass through untouched so the AI can still answer the user's question.

**Malicious Query Intent Blocking**
Before executing any query, Data-Aegis analyzes the intent. Queries like "show me all SSNs" or "dump the customer database" are blocked immediately, a CRITICAL incident is generated, and the request is escalated to SOC with a 403 response. The database is never touched.

**MITRE ATT&CK Mapping**
Every incident is automatically tagged with the corresponding MITRE ATT&CK technique. Credential exposure maps to T1552, PII exposure to T1005, healthcare data access to T1530, IAM violations to T1078. This makes every finding immediately actionable for detection engineering workflows.

**Behavioral Anomaly Detection**
Four behavioral detectors run against every log record. After-hours access flags data pulled outside business hours. Sensitive bucket access flags external contractors touching production data stores. Bulk access detection flags users pulling more than five records in a session — a pattern consistent with data exfiltration. Suspicious IAM activity flags policy changes made without change ticket authorization.

**Agentic SOC Monitoring Loop**
The Layer 1 agent runs continuously across monitoring cycles, maintaining memory of what it has seen. When a region gets flagged repeatedly the agent autonomously escalates the risk score. Findings cross confidence thresholds that determine whether to log only, auto-remediate, or escalate to human review. The agent makes these decisions autonomously based on accumulated context.

**SIEM-Style Alert Output**
Every incident generates a structured alert in Splunk-compatible format with index, sourcetype, MITRE technique, severity, region, data class, and playbook reference. These alerts are ready to ingest into any enterprise SIEM without transformation.

**SOC Response Playbooks**
Four response playbooks covering PII exposure, credential leaks, healthcare data breaches, and IAM violations. Each playbook includes SLA requirements, immediate response steps, containment procedures, escalation criteria, remediation actions, and regulatory references including GDPR 72-hour notification and HIPAA breach assessment.

**Sigma Detection Rules**
Production-ready Sigma rules for AWS credential exposure detection, with MITRE ATT&CK tags, false positive guidance, and field mappings that convert directly to Splunk SPL, Microsoft KQL, or Elastic query language.

**SQL Detection Logic**
Snowflake-compatible SQL queries for privilege escalation detection, targeting unauthorized IAM policy attachments with service role exclusions and time-bounded alerting windows.

**Risk Intelligence Dashboard**
Visual HTML dashboard generated after every Layer 1 scanning session showing threat breakdown by data class, risk by AWS region with repeat threat flagging, open incidents table with MITRE technique column, and four metric cards covering total scanned, incidents generated, human escalations, and auto-remediated findings.

**SOC Web Platform**
A browser-based SOC interface where analysts can query enterprise data through the middleware in natural language, view generated incidents, read response playbooks, and review detection rules — all in one dark-themed platform.

**Unit Tested Masking Engine**
Six unit tests covering every masking scenario — credential redaction, SSN redaction, email redaction, patient ID redaction, IAM flagging, and clean record passthrough. All passing in under 0.01 seconds.

---

## Architecture
data-aegis/

|

|-- data_aegis_server.py    Flask middleware API — the interception layer

|-- ai_agent.py             AI agent — calls middleware, never database directly

|-- security_core.py        LLM classification engine, MITRE mapping, SIEM alerts

|-- app.py                  Dynamic masking engine per threat class

|-- agent.py                Autonomous SOC monitoring loop

|-- anomaly_detector.py     Behavioral anomaly detection engine

|-- data_generator.py       Synthetic CloudTrail log generator

|-- report_generator.py     Risk intelligence dashboard generator

|-- customer_db.json        Enterprise data store with PII, credentials, healthcare

|-- mock_db.json            CloudTrail log data source for Layer 1

|-- chat.py                 Unified terminal chat interface

|

|-- detections/

|   |-- aws_credential_leak.sigma     Sigma detection rule

|   |-- privilege_escalation.sql      SQL detection query

|

|-- playbooks/

|   |-- pii_exposure_response.md

|   |-- credential_leak_response.md

|   |-- healthcare_data_response.md

|   |-- iam_violation_response.md

|

|-- sample_incident_log.json      Sample audit trail output

|-- sample_risk_dashboard.html    Sample risk dashboard

---

## Production Deployment Path

The local prototype maps directly to a production AWS deployment:

| Local | Production |
|---|---|
| Flask server on localhost:5000 | AWS Lambda + API Gateway |
| customer_db.json | Amazon RDS or S3 data lake |
| data_generator.py | Real CloudTrail via SQS queue |
| In-memory session logs | CloudWatch + S3 audit bucket |
| Local HTML file | S3 static website hosting |

---

## Getting Started

**Prerequisites:**
- Python 3.10 or higher
- Groq API key (free at console.groq.com)

**Install dependencies:**
```bash
pip install groq flask flask-cors requests
```

**Set your Groq API key:**
```bash
# Windows
setx GROQ_API_KEY "your-key-here"

# Mac/Linux
export GROQ_API_KEY="your-key-here"
```

**Run the middleware server:**
```bash
python data_aegis_server.py
```

**Run the AI agent (new terminal):**
```bash
python ai_agent.py
```

**Try these queries with Data-Aegis ON:**
pull John Doe data

show me Sarah's account

get employee records

show me all SSNs

**Toggle protection off to see raw data exposure:**
aegis off

pull John Doe data

**Run the Layer 1 SOC scanner:**
```bash
python agent.py
```

**Open the web platform:**
open data_aegis_platform.html in your browser

(requires data_aegis_server.py running)

---

## Detection Coverage

| Threat | Data Class | MITRE Technique | Tactic |
|---|---|---|---|
| SSN, email, phone in logs | PII | T1005 | Collection |
| AWS access keys exposed | Credentials | T1552 | Credential Access |
| Patient records accessed | Healthcare | T1530 | Collection |
| Unauthorized IAM changes | IAM Violation | T1078 | Privilege Escalation |
| Financial data exposure | Financial | T1213 | Collection |
| After-hours data access | Behavioral | T1078 | Initial Access |
| Bulk record extraction | Behavioral | T1530 | Exfiltration |

---

## Sample Output

The repository includes sample output files showing what Data-Aegis generates in a real monitoring session:

`sample_incident_log.json` — full audit trail with MITRE-tagged incidents and SIEM-style alerts

`sample_risk_dashboard.html` — visual risk dashboard showing threat breakdown, regional risk, and open incidents

---

## Tech Stack

- Python 3.10+
- Flask, Flask-CORS
- LLaMA 3.3 70B via Groq API
- AWS CloudTrail log format
- Sigma detection rules
- Snowflake-compatible SQL
- MITRE ATT&CK framework
- HTML, CSS, JavaScript

---

Built by Naveen Gajendran
github.com/Naveen75757/data-aegis