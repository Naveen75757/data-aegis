import json
import os
import re
import random
from datetime import datetime
from flask import Flask, request, jsonify
from flask_cors import CORS
from security_core import classify_log_entry, get_mitre_mapping, format_siem_alert
from app import apply_dynamic_masking
from anomaly_detector import run_anomaly_detection

# ============================================================
# DATA-AEGIS MIDDLEWARE SERVER
# Runs as a completely separate process on localhost:5000
# AI agents cannot access enterprise data without going
# through this server — true middleware interception
# ============================================================

app = Flask(__name__)
CORS(app)  # Allow cross-origin requests from web UI

# In-memory incident log for this server session
server_incidents = []
server_query_log = []


def load_customer_db():
    """Loads enterprise customer database"""
    with open("customer_db.json", "r") as f:
        return json.load(f)


def search_database(query):
    """Searches customer database for relevant records"""
    db = load_customer_db()
    query_lower = query.lower()
    results = []

    # Search customers
    for customer in db.get("customers", []):
        name_parts = customer["name"].lower().split()
        if any(part in query_lower for part in name_parts):
            results.append({"type": "customer", "data": customer})

    # Search employees
    if any(word in query_lower for word in ["employee", "staff", "admin", "engineer", "credential", "key", "aws"]):
        for employee in db.get("employees", []):
            results.append({"type": "employee", "data": employee})

    # Search healthcare
    if any(word in query_lower for word in ["health", "medical", "patient", "diagnosis"]):
        for record in db.get("healthcare_records", []):
            name_parts = record["name"].lower().split()
            if any(part in query_lower for part in name_parts) or "patient" in query_lower:
                results.append({"type": "healthcare", "data": record})

    return results


def mask_record(record, record_type):
    """Applies targeted masking per data class"""
    masked = json.loads(json.dumps(record))  # deep copy

    if record_type == "customer":
        sensitive_fields = []
        if "ssn" in masked:
            sensitive_fields.append({"field": "ssn", "class": "PII", "mitre": "T1005"})
            masked["ssn"] = "[REDACTED_NATIONAL_ID]"
        if "email" in masked:
            sensitive_fields.append({"field": "email", "class": "PII", "mitre": "T1005"})
            masked["email"] = "[REDACTED_EMAIL]"
        if "phone" in masked:
            sensitive_fields.append({"field": "phone", "class": "PII", "mitre": "T1005"})
            masked["phone"] = "[REDACTED_PHONE]"
        if "date_of_birth" in masked:
            sensitive_fields.append({"field": "date_of_birth", "class": "PII", "mitre": "T1005"})
            masked["date_of_birth"] = "[REDACTED_DOB]"
        return masked, sensitive_fields

    elif record_type == "employee":
        sensitive_fields = []
        if "aws_access_key" in masked:
            sensitive_fields.append({"field": "aws_access_key", "class": "Credentials", "mitre": "T1552"})
            masked["aws_access_key"] = "[REDACTED_AWS_CREDENTIAL]"
        if "aws_secret" in masked:
            sensitive_fields.append({"field": "aws_secret", "class": "Credentials", "mitre": "T1552"})
            masked["aws_secret"] = "[REDACTED_AWS_SECRET]"
        return masked, sensitive_fields

    elif record_type == "healthcare":
        sensitive_fields = []
        if "date_of_birth" in masked:
            sensitive_fields.append({"field": "date_of_birth", "class": "Healthcare", "mitre": "T1530"})
            masked["date_of_birth"] = "[REDACTED_DOB]"
        if "diagnosis_code" in masked:
            sensitive_fields.append({"field": "diagnosis_code", "class": "Healthcare", "mitre": "T1530"})
            masked["diagnosis_code"] = "[REDACTED_DIAGNOSIS_CODE]"
        if "diagnosis_name" in masked:
            sensitive_fields.append({"field": "diagnosis_name", "class": "Healthcare", "mitre": "T1530"})
            masked["diagnosis_name"] = "[REDACTED_DIAGNOSIS]"
        if "prescriptions" in masked:
            sensitive_fields.append({"field": "prescriptions", "class": "Healthcare", "mitre": "T1530"})
            masked["prescriptions"] = ["[REDACTED_PRESCRIPTION]"]
        if "insurance_id" in masked:
            sensitive_fields.append({"field": "insurance_id", "class": "Healthcare", "mitre": "T1530"})
            masked["insurance_id"] = "[REDACTED_INSURANCE_ID]"
        return masked, sensitive_fields

    return masked, []


def detect_malicious_intent(query):
    """Detects malicious query patterns before execution"""
    query_lower = query.lower()
    malicious_patterns = [
        r"all\s+(ssn|social security|passwords?|credentials?|secrets?|keys?)",
        r"dump\s+(database|db|all|customer|employee)",
        r"export\s+(all|everything|database|customer|data)",
        r"show\s+me\s+all\s+(ssn|passwords?|credentials?|keys?)",
        r"give\s+me\s+(all|every)\s+(ssn|password|credential|key|secret)",
        r"list\s+all\s+(credentials?|passwords?|ssn|keys?|secrets?)",
        r"master\s+(password|key|credential|secret)",
        r"bypass\s+(security|authentication|authorization)",
        r"extract\s+(all|every|bulk)\s+(data|records?|information)"
    ]
    for pattern in malicious_patterns:
        if re.search(pattern, query_lower):
            return True
    return False


# ============================================================
# API ENDPOINTS
# ============================================================

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        "status": "online",
        "service": "Data-Aegis Middleware",
        "version": "4.0",
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    })


@app.route('/query', methods=['POST'])
def intercept_query():
    """
    CORE MIDDLEWARE ENDPOINT
    Every AI agent query comes through here.
    This is true interception — the AI cannot access
    the database without going through this endpoint.
    """
    data = request.json
    query = data.get("query", "")
    aegis_enabled = data.get("aegis_enabled", True)

    # Log every query attempt
    log_entry = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "query": query,
        "aegis_enabled": aegis_enabled
    }

    # If Data-Aegis is OFF — return raw unprotected data
    if not aegis_enabled:
        results = search_database(query)
        raw_records = [r["data"] for r in results]
        log_entry["action"] = "UNPROTECTED_PASS_THROUGH"
        server_query_log.append(log_entry)
        return jsonify({
            "protected": False,
            "records": raw_records,
            "message": "⚠️ Data-Aegis DISABLED — raw sensitive data returned"
        })

    # Data-Aegis ON — full interception pipeline

    # Step 1 — Check for malicious intent
    if detect_malicious_intent(query):
        incident_id = f"INC-{random.randint(10000, 99999)}"
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
            "mitre_tactic": "Collection",
            "escalated_to": "SOC_AGENT_01",
            "playbook": "playbooks/pii_exposure_response.md"
        }
        server_incidents.append(incident)
        log_entry["action"] = "BLOCKED"
        log_entry["incident_id"] = incident_id
        server_query_log.append(log_entry)

        return jsonify({
            "protected": True,
            "blocked": True,
            "incident": incident,
            "message": f"⛔ Query blocked by Data-Aegis | Incident: {incident_id}"
        }), 403

    # Step 2 — Search database
    results = search_database(query)

    if not results:
        log_entry["action"] = "NO_RESULTS"
        server_query_log.append(log_entry)
        return jsonify({
            "protected": True,
            "blocked": False,
            "records": [],
            "message": "No records found"
        })

    # Step 3 — Classify and mask each record
    masked_results = []
    all_detections = []

    for result in results:
        record_type = result["type"]
        raw_record = result["data"]

        # Apply masking
        masked_record, sensitive_fields = mask_record(raw_record, record_type)

        if sensitive_fields:
            # Generate incident for sensitive data found
            incident_id = f"INC-{random.randint(10000, 99999)}"
            primary_class = sensitive_fields[0]["class"]
            mitre = get_mitre_mapping(primary_class)

            incident = {
                "incident_id": incident_id,
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "type": "SENSITIVE_DATA_INTERCEPTED",
                "severity": "HIGH",
                "risk_score": 7,
                "data_class": primary_class,
                "fields_masked": [f["field"] for f in sensitive_fields],
                "mitre_technique_id": mitre["technique_id"],
                "mitre_technique_name": mitre["technique_name"],
                "mitre_tactic": mitre["tactic"],
                "action": "MASKED",
                "playbook": f"playbooks/{primary_class.lower()}_exposure_response.md"
            }
            server_incidents.append(incident)
            all_detections.append({
                "record_type": record_type,
                "sensitive_fields": sensitive_fields,
                "incident_id": incident_id
            })

        masked_results.append({
            "type": record_type,
            "data": masked_record
        })

    log_entry["action"] = "MASKED" if all_detections else "CLEAN"
    log_entry["detections"] = len(all_detections)
    server_query_log.append(log_entry)

    return jsonify({
        "protected": True,
        "blocked": False,
        "records": masked_results,
        "detections": all_detections,
        "incidents": server_incidents[-len(all_detections):] if all_detections else [],
        "message": f"✅ Data-Aegis intercepted and masked {len(all_detections)} sensitive record(s)"
    })


@app.route('/incidents', methods=['GET'])
def get_incidents():
    """Returns all incidents generated this session"""
    return jsonify({
        "total": len(server_incidents),
        "incidents": server_incidents
    })


@app.route('/query-log', methods=['GET'])
def get_query_log():
    """Returns full query audit log"""
    return jsonify({
        "total": len(server_query_log),
        "log": server_query_log
    })


@app.route('/scan-logs', methods=['POST'])
def scan_cloudtrail():
    """
    Layer 1 — Triggers CloudTrail log scanning
    Runs existing agent.py logic and returns results
    """
    from data_generator import generate_live_stream
    from security_core import classify_log_entry
    from app import apply_dynamic_masking

    records = generate_live_stream(10)
    scan_results = []

    for row in records:
        log_content = row["service_log"]
        security_meta = classify_log_entry(log_content)

        if security_meta["contains_sensitive_data"]:
            mitre = get_mitre_mapping(security_meta["data_class"])
            sanitized = apply_dynamic_masking(log_content, security_meta["data_class"])
            scan_results.append({
                "ticket_id": row["ticket_id"],
                "region": row["region"],
                "source": row["source"],
                "risk_score": security_meta["risk_score"],
                "data_class": security_meta["data_class"],
                "risk_reasoning": security_meta["risk_reasoning"],
                "remediation": security_meta["remediation_action"],
                "mitre_technique_id": mitre["technique_id"],
                "mitre_technique_name": mitre["technique_name"],
                "mitre_tactic": mitre["tactic"],
                "safe_log": sanitized,
                "flagged": True
            })
        else:
            scan_results.append({
                "ticket_id": row["ticket_id"],
                "region": row["region"],
                "source": row["source"],
                "risk_score": security_meta["risk_score"],
                "risk_reasoning": security_meta["risk_reasoning"],
                "flagged": False
            })

    flagged = [r for r in scan_results if r["flagged"]]

    return jsonify({
        "total_scanned": len(scan_results),
        "flagged": len(flagged),
        "clean": len(scan_results) - len(flagged),
        "risk_rate": round(len(flagged) / len(scan_results) * 100),
        "results": scan_results
    })


@app.route('/status', methods=['GET'])
def get_status():
    """Returns current system status"""
    return jsonify({
        "status": "online",
        "total_queries": len(server_query_log),
        "total_incidents": len(server_incidents),
        "blocked_queries": len([q for q in server_query_log if q.get("action") == "BLOCKED"]),
        "masked_queries": len([q for q in server_query_log if q.get("action") == "MASKED"]),
    })


if __name__ == "__main__":
    print("\n" + "="*60)
    print("  🔒 DATA-AEGIS MIDDLEWARE SERVER")
    print("  AI Security Posture Management Gateway")
    print("  Version 4.0")
    print("="*60)
    print("  Endpoints:")
    print("  POST /query      — intercept AI agent queries")
    print("  POST /scan-logs  — trigger CloudTrail scan")
    print("  GET  /incidents  — view generated incidents")
    print("  GET  /query-log  — view query audit log")
    print("  GET  /status     — system status")
    print("  GET  /health     — health check")
    print("="*60)
    print("  Server starting on http://localhost:5000")
    print("="*60 + "\n")

    app.run(debug=True, port=5000)