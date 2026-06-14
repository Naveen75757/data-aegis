# Playbook: IAM Violation Response
**Trigger:** Data-Aegis detects unauthorized IAM policy changes, missing change tickets, or privilege escalation
**MITRE ATT&CK:** T1078 — Valid Accounts [Privilege Escalation]
**Severity:** HIGH to CRITICAL
**SLA:** Acknowledge within 15 minutes, revert unauthorized changes within 1 hour

---

## Immediate Response (0-15 mins)

1. **Acknowledge incident** — note actor ARN, policy changed, region, timestamp
2. **Identify the change** — what permissions were granted? To which account?
3. **Verify change ticket** — does a valid change ticket exist for this modification?
4. **If no change ticket — treat as unauthorized** — assume malicious until proven otherwise
5. **Identify the actor** — was this an admin account, service account, or external user?

---

## Containment (15-60 mins)

1. **Revert the policy change** if unauthorized — remove granted permissions immediately
2. **Suspend the actor account** if behavior looks malicious
3. **Review all actions taken by this account** in the last 24 hours via CloudTrail
4. **Check for persistence mechanisms** — did attacker create new IAM users or access keys?
5. **Enable MFA** on all privileged accounts if not already enabled

---

## Investigation

1. **Review Data-Aegis audit log** — full incident context with MITRE T1078 mapping
2. **Check Data-Aegis anomaly detection** — was after-hours access flagged simultaneously?
3. **Review CloudTrail for the actor** — what else did this account do?
4. **Check for lateral movement** — did the escalated account access sensitive resources?
5. **Determine intent** — misconfiguration, lazy admin, or active attack?

---

## Privilege Escalation Indicators

High confidence attack indicators:
- Policy change outside business hours — Data-Aegis after-hours detector fires
- Actor account has no history of IAM changes
- Policy grants AdministratorAccess or S3FullAccess
- Multiple IAM changes in short succession
- Change immediately followed by sensitive data access

---

## Escalation Criteria

Escalate to CISO immediately if:
- AdministratorAccess was granted
- Evidence of subsequent data exfiltration
- External or contractor account made the change
- Multiple accounts affected
- Active attack in progress

---

## Remediation

1. **Revert all unauthorized policy changes** — use AWS Config to restore previous state
2. **Implement IAM policy guardrails** — use AWS Organizations SCPs to prevent dangerous policies
3. **Enforce change management** — all IAM changes require approved change ticket
4. **Enable AWS CloudTrail alerts** — real-time notification on IAM policy changes
5. **Implement least-privilege** — review all IAM roles for excessive permissions
6. **Enable AWS Access Analyzer** — continuously analyze resource policies for overly permissive access

---

## Post Incident Review

1. **Change management audit** — why was a policy changed without a ticket?
2. **IAM hygiene review** — full audit of all IAM roles and policies
3. **Detection tuning** — update Data-Aegis IAM violation thresholds
4. **Process improvement** — strengthen change management procedures
5. **Red team exercise** — test privilege escalation detection capabilities

---

## AWS Specific Hardening
- Enable AWS Config Rules for IAM compliance
- Implement AWS Organizations Service Control Policies
- Enable GuardDuty IAM finding types
- Use AWS IAM Access Analyzer for policy validation
- Implement break-glass account procedures for emergency access