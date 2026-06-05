import json
import re
from security_core import classify_log_entry

def apply_dynamic_masking(text, data_class):
    """
    Programmatically sanitizes data fields based on 
    Data-Aegis AI classification metadata.
    
    This mirrors Cyera's dynamic data masking capability —
    instead of blanket redaction, we apply targeted masking
    based on exactly what type of sensitive data was detected.
    """
    if data_class == "Credentials":
        # Redact AWS access keys
        text = re.sub(r'AKIA[A-Z0-9]{16}', '[REDACTED_AWS_CREDENTIAL]', text)
        # Redact any generic secrets/tokens
        text = re.sub(r'(?i)(secret|token|password|key)\s*[:=]\s*\S+', '[REDACTED_SECRET]', text)
        return text
    
    elif data_class == "PII":
        # Redact SSNs
        text = re.sub(r'\d{3}-\d{2}-\d{4}', '[REDACTED_NATIONAL_ID]', text)
        # Redact emails
        text = re.sub(r'[\w\.-]+@[\w\.-]+', '[REDACTED_EMAIL]', text)
        # Redact full names (basic pattern)
        text = re.sub(r'(?i)(customer|user|name)\s+[A-Z][a-z]+\s+[A-Z][a-z]+', '[REDACTED_NAME]', text)
        return text
    
    elif data_class == "Healthcare":
        # Redact patient IDs
        text = re.sub(r'(?i)patient\s*id\s*\d+', '[REDACTED_PATIENT_ID]', text)
        # Redact dates of birth
        text = re.sub(r'\d{2}/\d{2}/\d{4}', '[REDACTED_DOB]', text)
        # Redact ICD-10 diagnosis codes
        text = re.sub(r'(?i)icd-10\s+[A-Z]\d+\.?\d*', '[REDACTED_DIAGNOSIS_CODE]', text)
        return text
    
    elif data_class == "IAM_Violation":
        # Don't mask — flag it for human review instead
        return text + " [⚠️ IAM_VIOLATION_FLAGGED_FOR_REVIEW]"
    
    return text


def generate_audit_report(results):
    """
    Generates a structured audit report from all processed records.
    This is what Cyera delivers to enterprise compliance teams.
    """
    total = len(results)
    flagged = [r for r in results if r["risk_detected"]]
    clean = [r for r in results if not r["risk_detected"]]
    
    print("\n")
    print("=" * 60)
    print("       DATA-AEGIS AI-SPM AUDIT REPORT")
    print("       Powered by AI-Native Data Classification")
    print("=" * 60)
    print(f"  Total Records Scanned:     {total}")
    print(f"  Clean Records:             {len(clean)}")
    print(f"  Flagged & Remediated:      {len(flagged)}")
    print(f"  Risk Rate:                 {round(len(flagged)/total*100)}%")
    print("=" * 60)
    
    if flagged:
        print("\n  FLAGGED RECORDS SUMMARY:")
        for r in flagged:
            print(f"\n  Ticket: {r['ticket_id']}")
            print(f"  Data Class:  {r['data_class']}")
            print(f"  Risk Score:  {r['risk_score']}/10")
            print(f"  Reasoning:   {r['risk_reasoning']}")
            print(f"  Action:      {r['remediation_action']}")
    
    print("\n" + "=" * 60)
    print("  ✅ Safe payload ready for downstream AI agent consumption")
    print("=" * 60 + "\n")


def main():
    print("\n🔒 Initializing Data-Aegis AI Security Posture Management Gateway...")
    print("   Scanning enterprise data store for sensitive exposure...\n")
    
    with open("mock_db.json", "r") as f:
        database_rows = json.load(f)
    
    safe_context_for_ai_agent = []
    audit_results = []
    
    for row in database_rows:
        log_content = row["service_log"]
        print(f"📥 Scanning Record [{row['ticket_id']}] | Source: {row['source']} | Region: {row['region']}")
        
        # Run through Data-Aegis AI classification engine
        security_meta = classify_log_entry(log_content)
        
        if security_meta["contains_sensitive_data"]:
            print(f"   🚨 RISK DETECTED | Class: {security_meta['data_class']} | Score: {security_meta['risk_score']}/10")
            print(f"   📋 Reasoning: {security_meta['risk_reasoning']}")
            
            # Apply targeted dynamic masking based on data class
            sanitized_log = apply_dynamic_masking(log_content, security_meta["data_class"])
            print(f"   🛡️  Remediation: {security_meta['remediation_action']} applied")
            
            audit_results.append({
                "ticket_id": row["ticket_id"],
                "risk_detected": True,
                "data_class": security_meta["data_class"],
                "risk_score": security_meta["risk_score"],
                "risk_reasoning": security_meta["risk_reasoning"],
                "remediation_action": security_meta["remediation_action"]
            })
        else:
            print(f"   ✅ CLEAR | {security_meta['risk_reasoning']}")
            sanitized_log = log_content
            
            audit_results.append({
                "ticket_id": row["ticket_id"],
                "risk_detected": False,
                "data_class": "None",
                "risk_score": 0,
                "risk_reasoning": security_meta["risk_reasoning"],
                "remediation_action": "None"
            })
        
        safe_context_for_ai_agent.append({
            "ticket_id": row["ticket_id"],
            "source": row["source"],
            "region": row["region"],
            "safe_log": sanitized_log
        })
        
        print("-" * 60)
    
    # Generate audit report
    generate_audit_report(audit_results)
    
    # Output clean safe payload
    print("🚀 SAFE DATA PAYLOAD FOR AI AGENT:")
    print(json.dumps(safe_context_for_ai_agent, indent=2))


if __name__ == "__main__":
    main()