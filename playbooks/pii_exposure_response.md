# Playbook: PII Exposure Response
**Trigger:** Data-Aegis detects PII (SSN, email, name) in enterprise log stream
**MITRE ATT&CK:** T1005 — Data from Local System [Collection]
**Severity:** HIGH to CRITICAL
**SLA:** Acknowledge within 15 minutes, contain within 1 hour

---

## Immediate Response (0-15 mins)

1. **Acknowledge the incident** in Data-Aegis incident log
2. **Identify the source record** — note ticket_id, region, timestamp
3. **Verify masking was applied** — confirm [REDACTED] tokens in safe_log output
4. **Identify the data subject** — who does the PII belong to?
5. **Identify the accessor** — which user or AI agent triggered the request?

---

## Containment (15-60 mins)

1. **Suspend the accessor account** if behavior looks malicious
2. **Review access logs** — how many records did this user access?
3. **Check for bulk access patterns** — Data-Aegis bulk detector threshold is 5 records
4. **Notify data owner** — inform the team responsible for the dataset
5. **Preserve evidence** — do not modify original logs, work from audit trail copy

---

## Investigation

1. **Review Data-Aegis audit log** — `sample_incident_log.json`
2. **Check agent memory summary** — was this region flagged repeatedly?
3. **Review MITRE mapping** — T1005 suggests adversary collecting data from local system
4. **Determine if breach occurred** — was unmasked PII exposed to unauthorized party?
5. **Scope the exposure** — how many records, which data subjects affected?

---

## Escalation Criteria

Escalate to Security Leadership if:
- More than 10 records exposed in single session
- External contractor account was the accessor
- Access occurred outside business hours
- Same user flagged in multiple regions

---

## Remediation

1. **Rotate credentials** of compromised or suspicious accounts
2. **Review IAM permissions** — does this user need access to this dataset?
3. **Apply data minimization** — remove unnecessary PII from operational logs
4. **Update detection rules** — tune Data-Aegis classification thresholds if false positive
5. **Notify affected individuals** if breach confirmed — check GDPR 72-hour notification requirement

---

## Post Incident Review

1. **Document timeline** — from detection to containment
2. **Root cause analysis** — how did PII end up in operational logs?
3. **Update playbook** — did this playbook work? What needs improving?
4. **Report to compliance team** — file incident report for regulatory audit trail
5. **Tune detection** — adjust risk scoring thresholds based on findings

---

## GDPR Considerations
If EU data subjects are affected:
- 72-hour breach notification to supervisory authority
- Notify affected individuals without undue delay
- Document breach in Data-Aegis audit log for accountability record