import json
import os
import re
from datetime import datetime
from groq import Groq
from security_core import classify_log_entry, get_mitre_mapping, format_siem_alert
from app import apply_dynamic_masking
from anomaly_detector import run_anomaly_detection

# ============================================================
# DATA-AEGIS UNIFIED CHAT INTERFACE
# Single entry point for both security layers:
# Layer 1 — Continuous audit scanner (CloudTrail logs)
# Layer 2 — Real-time data middleware (enterprise queries)
# ============================================================

client = Groq()

# Session activity log — records every query made
session_log = []
session_incidents = []


def log_session_activity(query, intent, action, risk_score=0, data_class=None, mitre=None):
    """Records every query to session activity log for Layer 1 audit scanning"""
    entry = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "query": query,
        "intent": intent,
        "action": action,
        "risk_score": risk_score,
        "data_class": data_class or "None",
        "mitre_technique": mitre or "N/A"
    }
    session_log.append(entry)
    return entry


def analyze_query_intent(query):
    """
    Analyzes user query for malicious or suspicious intent
    BEFORE executing anything.
    Three categories:
    - MALICIOUS: block immediately
    - LAYER1: route to log scanner
    - LAYER2: route to data middleware
    - GENERAL: help, status, exit
    """
    query_lower = query.lower()

    # Malicious intent patterns — block these immediately
    malicious_patterns = [
        r"all\s+(ssn|social security|passwords?|credentials?|secrets?|keys?)",
        r"dump\s+(database|db|all|customer|employee)",
        r"export\s+(all|everything|database|customer|data)",
        r"show\s+me\s+all\s+(ssn|passwords?|credentials?|keys?|secrets?)",
        r"give\s+me\s+(all|every)\s+(ssn|password|credential|key|secret)",
        r"list\s+all\s+(credentials?|passwords?|ssn|keys?|secrets?)",
        r"aws\s+(secret|master|admin)\s+key",
        r"master\s+(password|key|credential|secret)",
        r"bypass\s+(security|authentication|authorization)",
        r"extract\s+(all|every|bulk)\s+(data|records?|information)"
    ]

    for pattern in malicious_patterns:
        if re.search(pattern, query_lower):
            return "MALICIOUS"

    # Layer 1 — Log scanner triggers
    layer1_patterns = [
        "scan", "audit", "security events", "recent logs",
        "check logs", "threat", "incidents", "security scan",
        "cloudtrail", "show events", "session logs", "activity"
    ]
    for pattern in layer1_patterns:
        if pattern in query_lower:
            return "LAYER1"

    # Layer 2 — Data middleware triggers
    layer2_patterns = [
        "pull", "get", "show me", "find", "retrieve",
        "customer", "account", "employee", "patient",
        "record", "data", "profile", "information",
        "john", "sarah", "michael", "emily", "david"
    ]
    for pattern in layer2_patterns:
        if pattern in query_lower:
            return "LAYER2"

    # General commands
    if any(word in query_lower for word in ["help", "status", "exit", "quit", "clear"]):
        return "GENERAL"

    return "LAYER2"


def handle_malicious_query(query):
    """Blocks malicious queries and generates incident"""
    import random
    mitre = get_mitre_mapping("PII")

    incident_id = f"INC-{random.randint(10000, 99999)}"

    print(f"\n{'='*60}")
    print(f"  ⛔ DATA-AEGIS SECURITY ALERT")
    print(f"{'='*60}")
    print(f"  SUSPICIOUS QUERY DETECTED AND BLOCKED")
    print(f"  Query: '{query}'")
    print(f"  Risk Score: 9/10")
    print(f"  MITRE: T1005 — Data from Local System [Collection]")
    print(f"  Incident: {incident_id}")
    print(f"  Action: QUERY BLOCKED — not executed")
    print(f"  Escalated to: SOC_AGENT_01")
    print(f"  Playbook: playbooks/pii_exposure_response.md")
    print(f"{'='*60}\n")

    log_session_activity(
        query=query,
        intent="MALICIOUS",
        action="BLOCKED",
        risk_score=9,
        data_class="Suspicious_Query",
        mitre="T1005"
    )

    incident = {
        "incident_id": incident_id,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "type": "MALICIOUS_QUERY",
        "query": query,
        "severity": "CRITICAL",
        "risk_score": 9,
        "action": "BLOCKED",
        "mitre_technique_id": "T1005",
        "mitre_technique_name": "Data from Local System",
        "escalated_to": "SOC_AGENT_01"
    }
    session_incidents.append(incident)


def search_customer_db(query):
    """Searches customer_db.json for relevant records"""
    with open("customer_db.json", "r") as f:
        db = json.load(f)

    query_lower = query.lower()
    results = []

    # Search customers
    for customer in db.get("customers", []):
        if any(word in customer["name"].lower() for word in query_lower.split()):
            results.append({"type": "customer", "data": customer})

    # Search employees if query mentions employee/staff/credentials
    if any(word in query_lower for word in ["employee", "staff", "admin", "engineer", "credential", "key"]):
        for employee in db.get("employees", []):
            if any(word in employee["name"].lower() for word in query_lower.split()) or \
               any(word in query_lower for word in ["employee", "staff", "all"]):
                results.append({"type": "employee", "data": employee})

    # Search healthcare records
    if any(word in query_lower for word in ["health", "medical", "patient", "diagnosis", "prescription"]):
        for record in db.get("healthcare_records", []):
            if any(word in record["name"].lower() for word in query_lower.split()) or \
               any(word in query_lower for word in ["health", "medical", "patient"]):
                results.append({"type": "healthcare", "data": record})

    return results


def mask_record(record, record_type):
    """Applies Data-Aegis masking to a database record"""
    masked = record.copy()

    if record_type == "customer":
        if "ssn" in masked:
            masked["ssn"] = "[REDACTED_NATIONAL_ID]"
        if "email" in masked:
            masked["email"] = "[REDACTED_EMAIL]"
        if "phone" in masked:
            masked["phone"] = "[REDACTED_PHONE]"
        if "date_of_birth" in masked:
            masked["date_of_birth"] = "[REDACTED_DOB]"

    elif record_type == "employee":
        if "aws_access_key" in masked:
            masked["aws_access_key"] = "[REDACTED_AWS_CREDENTIAL]"
        if "aws_secret" in masked:
            masked["aws_secret"] = "[REDACTED_AWS_SECRET]"

    elif record_type == "healthcare":
        if "date_of_birth" in masked:
            masked["date_of_birth"] = "[REDACTED_DOB]"
        if "diagnosis_code" in masked:
            masked["diagnosis_code"] = "[REDACTED_DIAGNOSIS_CODE]"
        if "diagnosis_name" in masked:
            masked["diagnosis_name"] = "[REDACTED_DIAGNOSIS]"
        if "prescriptions" in masked:
            masked["prescriptions"] = ["[REDACTED_PRESCRIPTION]"]
        if "insurance_id" in masked:
            masked["insurance_id"] = "[REDACTED_INSURANCE_ID]"

    return masked


def handle_layer2_query(query):
    """
    Layer 2 — Data Middleware
    Intercepts enterprise data queries, masks sensitive fields,
    passes only clean data to AI agent for response
    """
    print(f"\n🔒 Data-Aegis Layer 2 — Middleware intercepting query...")
    print(f"   Searching enterprise data store...\n")

    results = search_customer_db(query)

    if not results:
        print("   No records found matching your query.\n")
        log_session_activity(query, "LAYER2", "NO_RESULTS")
        return

    for result in results:
        record_type = result["type"]
        raw_record = result["data"]

        print(f"   📋 Record found: {raw_record.get('name', raw_record.get('employee_id', 'Unknown'))}")
        print(f"   Type: {record_type.upper()}")
        print(f"\n   🔍 Data-Aegis scanning for sensitive fields...")

        # Detect sensitive fields
        sensitive_fields = []
        if record_type == "customer":
            if "ssn" in raw_record:
                sensitive_fields.append(("SSN", "PII", "T1005"))
            if "email" in raw_record:
                sensitive_fields.append(("Email", "PII", "T1005"))
            if "date_of_birth" in raw_record:
                sensitive_fields.append(("Date of Birth", "PII", "T1005"))
        elif record_type == "employee":
            if "aws_access_key" in raw_record:
                sensitive_fields.append(("AWS Access Key", "Credentials", "T1552"))
            if "aws_secret" in raw_record:
                sensitive_fields.append(("AWS Secret Key", "Credentials", "T1552"))
        elif record_type == "healthcare":
            if "diagnosis_code" in raw_record:
                sensitive_fields.append(("Diagnosis Code", "Healthcare", "T1530"))
            if "prescriptions" in raw_record:
                sensitive_fields.append(("Prescriptions", "Healthcare", "T1530"))

        if sensitive_fields:
            print(f"\n   🚨 Sensitive fields detected:")
            for field, data_class, mitre in sensitive_fields:
                print(f"      • {field} — {data_class} | MITRE: {mitre}")

            # Apply masking
            masked_record = mask_record(raw_record, record_type)
            print(f"\n   🛡️  Data-Aegis masking applied...")
            print(f"   ✅ Clean record ready for AI agent\n")

            # Log the activity
            log_session_activity(
                query=query,
                intent="LAYER2",
                action="MASKED",
                risk_score=7,
                data_class=sensitive_fields[0][1],
                mitre=sensitive_fields[0][2]
            )

            # Generate AI response using masked data
            ai_response = generate_ai_response(query, [masked_record])
            print(f"   🤖 AI Agent Response:")
            print(f"   {ai_response}\n")

        else:
            print(f"   ✅ No sensitive fields detected — passing record to AI\n")
            log_session_activity(query, "LAYER2", "CLEAN")
            ai_response = generate_ai_response(query, [raw_record])
            print(f"   🤖 AI Agent Response:")
            print(f"   {ai_response}\n")


def generate_ai_response(query, clean_records):
    """
    Generates AI response using ONLY masked clean data.
    The AI never sees raw sensitive fields.
    """
    context = json.dumps(clean_records, indent=2)

    prompt = f"""You are an enterprise AI assistant. Answer the user's question using ONLY the sanitized data provided.
All sensitive fields have already been masked by Data-Aegis security middleware.
Never reference or reveal masked fields. Keep response concise and professional.

User question: {query}

Sanitized data:
{context}"""

    response = client.chat.completions.create(
        model="llama-3.3-70b-versatile",
        messages=[{"role": "user", "content": prompt}],
        temperature=0,
        max_tokens=300
    )

    return response.choices[0].message.content.strip()


def handle_layer1_scan(query):
    """
    Layer 1 — Audit Scanner
    Two modes: simulated CloudTrail or session activity logs
    """
    query_lower = query.lower()

    if "session" in query_lower or "activity" in query_lower or "chat" in query_lower:
        # Scan session activity logs
        print(f"\n🔍 Data-Aegis Layer 1 — Scanning session activity logs...\n")

        if not session_log:
            print("   No session activity yet.\n")
            return

        print(f"   {'='*50}")
        print(f"   SESSION ACTIVITY AUDIT REPORT")
        print(f"   {'='*50}")

        for entry in session_log:
            action_icon = "⛔" if entry["action"] == "BLOCKED" else "🛡️" if entry["action"] == "MASKED" else "✅"
            print(f"\n   {action_icon} {entry['timestamp']}")
            print(f"   Query: '{entry['query']}'")
            print(f"   Action: {entry['action']} | Risk: {entry['risk_score']}/10")
            if entry["mitre_technique"] != "N/A":
                print(f"   MITRE: {entry['mitre_technique']}")

        blocked = len([e for e in session_log if e["action"] == "BLOCKED"])
        masked = len([e for e in session_log if e["action"] == "MASKED"])
        clean = len([e for e in session_log if e["action"] == "CLEAN"])

        print(f"\n   {'='*50}")
        print(f"   Total Queries: {len(session_log)}")
        print(f"   Blocked: {blocked} | Masked: {masked} | Clean: {clean}")
        print(f"   {'='*50}\n")

    else:
        # Scan simulated CloudTrail stream
        print(f"\n🔍 Data-Aegis Layer 1 — Scanning CloudTrail log stream...\n")

        from data_generator import generate_live_stream
        from agent import run_agent

        database_rows = generate_live_stream(10)
        run_agent(database_rows, cycles=2)


def handle_general(query):
    """Handles help, status, and other general commands"""
    query_lower = query.lower()

    if "help" in query_lower:
        print(f"""
╔══════════════════════════════════════════════════════════╗
║         DATA-AEGIS — Available Commands                  ║
╠══════════════════════════════════════════════════════════╣
║  LAYER 2 — Data Middleware (Query Enterprise Data)       ║
║  • "pull [name] data" — get customer record              ║
║  • "show [name] account" — view account details          ║
║  • "get employee records" — query employee data          ║
║  • "find patient [name]" — query healthcare records      ║
║                                                          ║
║  LAYER 1 — Audit Scanner (Scan Logs)                     ║
║  • "scan recent logs" — scan CloudTrail stream           ║
║  • "scan session activity" — audit this chat session     ║
║  • "show security events" — run threat detection         ║
║                                                          ║
║  GENERAL                                                 ║
║  • "status" — show system status                         ║
║  • "help" — show this menu                               ║
║  • "exit" — quit Data-Aegis                              ║
╚══════════════════════════════════════════════════════════╝
        """)

    elif "status" in query_lower:
        print(f"""
╔══════════════════════════════════════════════════════════╗
║         DATA-AEGIS — System Status                       ║
╠══════════════════════════════════════════════════════════╣
║  🟢 Classification Engine    ONLINE                      ║
║  🟢 Anomaly Detector         ONLINE                      ║
║  🟢 MITRE ATT&CK Mapper      ONLINE                      ║
║  🟢 Dynamic Masking Engine   ONLINE                      ║
║  🟢 Audit Logger             ONLINE                      ║
║  🟢 Incident Generator       ONLINE                      ║
╠══════════════════════════════════════════════════════════╣
║  Session Queries:    {len(session_log):<35}║
║  Incidents Generated:{len(session_incidents):<35}║
╚══════════════════════════════════════════════════════════╝
        """)

    elif "exit" in query_lower or "quit" in query_lower:
        print("\n🔒 Data-Aegis shutting down. Session activity logged.\n")
        return True

    return False


def main():
    print(f"""
╔══════════════════════════════════════════════════════════╗
║                                                          ║
║         🔒 DATA-AEGIS AI SECURITY MIDDLEWARE             ║
║         AI Security Posture Management Gateway           ║
║                                                          ║
║         Layer 1: Continuous Audit Scanner                ║
║         Layer 2: Real-Time Data Middleware               ║
║                                                          ║
║         Type 'help' for available commands               ║
║                                                          ║
╚══════════════════════════════════════════════════════════╝
    """)

    while True:
        try:
            query = input("You: ").strip()

            if not query:
                continue

            # Detect intent
            intent = analyze_query_intent(query)

            if intent == "MALICIOUS":
                handle_malicious_query(query)

            elif intent == "LAYER1":
                handle_layer1_scan(query)

            elif intent == "LAYER2":
                handle_layer2_query(query)

            elif intent == "GENERAL":
                should_exit = handle_general(query)
                if should_exit:
                    break

        except KeyboardInterrupt:
            print("\n\n🔒 Data-Aegis shutting down.\n")
            break


if __name__ == "__main__":
    main()