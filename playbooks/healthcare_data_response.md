# Playbook: Healthcare Data Exposure Response
**Trigger:** Data-Aegis detects HIPAA-regulated data (patient ID, DOB, diagnosis codes) in log stream
**MITRE ATT&CK:** T1530 — Data from Cloud Storage [Collection]
**Severity:** CRITICAL — HIPAA breach notification rules apply
**SLA:** Acknowledge within 15 minutes, legal notification assessment within 24 hours

---

## Immediate Response (0-15 mins)

1. **Acknowledge incident** — note incident ID, timestamp, region from Data-Aegis log
2. **Identify the patient record** — which patient ID was exposed?
3. **Identify the accessor** — which account triggered the data access?
4. **Verify masking** — confirm patient ID, DOB, and ICD-10 code were redacted in safe_log
5. **Notify Privacy Officer immediately** — HIPAA requires designated privacy officer involvement

---

## Containment (15-60 mins)

1. **Suspend accessor account** if external contractor or anomalous behavior detected
2. **Preserve all evidence** — do not modify logs, Data-Aegis audit trail is your evidence
3. **Identify all affected records** — scope the full exposure
4. **Restrict dataset access** — temporarily limit access to affected healthcare bucket
5. **Document everything** — HIPAA breach response requires detailed documentation

---

## Investigation

1. **Review Data-Aegis audit log** — full incident metadata including MITRE mapping
2. **Check anomaly detection results** — was after-hours access or bulk access flagged?
3. **Determine if PHI was actually viewed** — was data masked before AI agent consumed it?
4. **Identify business associate involvement** — was a contractor or vendor the accessor?
5. **Assess unauthorized disclosure** — did unmasked PHI reach an unauthorized party?

---

## HIPAA Breach Assessment

Conduct the four-factor test:
1. Nature and extent of PHI involved
2. Who accessed or could have accessed the PHI
3. Whether PHI was actually acquired or viewed
4. Extent to which risk has been mitigated

If breach confirmed:
- **Individual notification** — within 60 days of discovery
- **HHS notification** — within 60 days if 500+ individuals affected
- **Media notification** — if 500+ residents of a state affected

---

## Escalation Criteria

Escalate to Legal and CISO immediately if:
- External contractor was the accessor
- Access occurred outside business hours — Data-Aegis after-hours detector fired
- Bulk access pattern detected — possible mass exfiltration
- More than 500 patient records potentially affected

---

## Remediation

1. **Review access controls** — should this account have healthcare data access?
2. **Apply data minimization** — remove diagnosis codes from operational logs
3. **Implement field-level encryption** — encrypt PHI fields at rest
4. **Update Business Associate Agreements** — ensure vendors have proper HIPAA agreements
5. **Retrain staff** — HIPAA awareness training for anyone handling PHI

---

## Post Incident Review

1. **Breach notification decision** — document the four-factor test outcome
2. **Root cause analysis** — how did PHI end up in CloudTrail logs?
3. **Update Data-Aegis thresholds** — tune healthcare detection sensitivity
4. **File with compliance team** — maintain breach log for HHS audit readiness
5. **Update playbook** — incorporate lessons learned

---

## Regulatory References
- HIPAA Breach Notification Rule — 45 CFR §§ 164.400-414
- HITECH Act breach notification requirements
- State-level health data breach notification laws