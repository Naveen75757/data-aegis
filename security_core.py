import json
import os
from groq import Groq

# Initialize the Groq client
# Automatically picks up your GROQ_API_KEY environment variable
client = Groq()

# Defined outside the function so it's not recreated on every call
system_prompt = """
You are an enterprise AI Data Security classification engine, similar to Cyera's AI Guardian platform.

Analyze the following AWS CloudTrail log entry and identify if it contains any of these sensitive data classes:
- Credentials (AWS keys, passwords, tokens, secrets)
- PII (names, SSNs, emails, phone numbers, dates of birth)
- Healthcare (patient IDs, diagnosis codes, medical records - HIPAA relevant)
- Financial (credit cards, bank accounts, transaction amounts tied to individuals)
- IAM Violation (unauthorized permission changes, missing change tickets, privilege escalation)

Return ONLY a valid JSON object with exactly these keys:
{
  "contains_sensitive_data": true or false,
  "data_class": "None" or "Credentials" or "PII" or "Healthcare" or "Financial" or "IAM_Violation",
  "risk_score": a number from 0 to 10,
  "risk_reasoning": "one sentence explaining why this is risky or safe",
  "remediation_action": "None" or "Mask_Credentials" or "Mask_PII" or "Mask_Healthcare" or "Flag_IAM"
}

Return nothing else. No explanation. No markdown. Just the JSON object.
"""

# ============================================================
# MITRE ATT&CK MAPPING
# Maps Data-Aegis threat classifications to real MITRE ATT&CK
# techniques — the universal framework used by SOC teams
# worldwide to classify and communicate security threats.
# ============================================================

MITRE_MAPPING = {
    "Credentials": {
        "technique_id": "T1552",
        "technique_name": "Unsecured Credentials",
        "tactic": "Credential Access",
        "description": "Adversaries search for unsecured credentials in logs, config files, and data stores",
        "url": "https://attack.mitre.org/techniques/T1552/"
    },
    "PII": {
        "technique_id": "T1005",
        "technique_name": "Data from Local System",
        "tactic": "Collection",
        "description": "Adversaries collect sensitive personal data from enterprise systems and databases",
        "url": "https://attack.mitre.org/techniques/T1005/"
    },
    "Healthcare": {
        "technique_id": "T1530",
        "technique_name": "Data from Cloud Storage",
        "tactic": "Collection",
        "description": "Adversaries access protected health information stored in cloud storage objects",
        "url": "https://attack.mitre.org/techniques/T1530/"
    },
    "Financial": {
        "technique_id": "T1213",
        "technique_name": "Data from Information Repositories",
        "tactic": "Collection",
        "description": "Adversaries collect financial records from enterprise information repositories",
        "url": "https://attack.mitre.org/techniques/T1213/"
    },
    "IAM_Violation": {
        "technique_id": "T1078",
        "technique_name": "Valid Accounts",
        "tactic": "Privilege Escalation",
        "description": "Adversaries obtain and abuse credentials of existing accounts to gain elevated permissions",
        "url": "https://attack.mitre.org/techniques/T1078/"
    },
    "Unknown": {
        "technique_id": "T1unknown",
        "technique_name": "Undetermined Technique",
        "tactic": "Unknown",
        "description": "Classification failed — manual investigation required",
        "url": "https://attack.mitre.org/techniques/"
    }
}


def get_mitre_mapping(data_class):
    """
    Returns MITRE ATT&CK technique for a given data class.
    Defaults to Unknown if data class not in mapping.
    """
    return MITRE_MAPPING.get(data_class, MITRE_MAPPING["Unknown"])

def format_siem_alert(incident):
    """
    Formats a Data-Aegis incident as a Splunk-style SIEM alert.
    Shows how findings integrate into enterprise SIEM workflows.
    Real SOC teams consume alerts in this format from Splunk,
    Microsoft Sentinel, or Elastic SIEM.
    """
    mitre = get_mitre_mapping(incident.get("data_class", "Unknown"))
    
    return {
        "alert_name": f"Data-Aegis: {incident.get('data_class')} Exposure Detected",
        "index": "cloudtrail",
        "sourcetype": "aws:cloudtrail",
        "severity": incident.get("severity", "HIGH"),
        "risk_score": incident.get("risk_score", 0),
        "mitre_technique": mitre["technique_id"],
        "mitre_tactic": mitre["tactic"],
        "dest_region": incident.get("region"),
        "source_record": incident.get("source_record"),
        "data_class": incident.get("data_class"),
        "remediation": incident.get("remediation_applied"),
        "escalate": incident.get("escalate_to_human", False),
        "playbook": f"playbooks/{incident.get('data_class', '').lower()}_exposure_response.md",
        "timestamp": incident.get("timestamp"),
        "assigned_to": incident.get("assigned_to", "SOC_AGENT_01")
    }

def classify_log_entry(raw_log_text):
    """
    Data-Aegis Classification Engine.
    
    Mimics Cyera's AI-native data classification approach —
    instead of dumb regex, we use an LLM to READ context and 
    identify hidden sensitive data classes in unstructured text.
    
    Returns structured risk metadata for every log entry.
    """
    try:
        response = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": f"Classify this log entry:\n\n{raw_log_text}"}
            ],
            temperature=0,
            max_tokens=256
        )
        
        response_text = response.choices[0].message.content.strip()
        
        # Remove markdown code blocks if model adds them
        if response_text.startswith("```"):
            response_text = response_text.split("```")[1]
            if response_text.startswith("json"):
                response_text = response_text[4:]
        
        return json.loads(response_text.strip())
    
    except json.JSONDecodeError:
        # LLM returned malformed JSON — fail safe, flag for review
        print("  ⚠️  Classification parse error — defaulting to safe mode")
        return {
            "contains_sensitive_data": True,
            "data_class": "Unknown",
            "risk_score": 5,
            "risk_reasoning": "Classification failed — flagged for manual review",
            "remediation_action": "Flag_For_Review"
        }
    
    except Exception as e:
        # API unavailable or any other error — always fail safe
        print(f"  ⚠️  API error: {str(e)} — record flagged for manual review")
        return {
            "contains_sensitive_data": True,
            "data_class": "Unknown",
            "risk_score": 5,
            "risk_reasoning": "API unavailable — flagged for manual review",
            "remediation_action": "Flag_For_Review"
        }