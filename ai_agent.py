import json
import requests
from groq import Groq

# ============================================================
# DATA-AEGIS AI AGENT
# A separate process that queries enterprise data through
# the Data-Aegis middleware API.
# 
# WITH Data-Aegis ON:
#   Agent calls localhost:5000 — gets masked clean data
#   Never sees raw SSNs, credentials, or PHI
#
# WITH Data-Aegis OFF:
#   Agent queries database directly — sees everything raw
#   SSNs, AWS keys, patient data all exposed
#
# This demonstrates true middleware interception —
# the agent is physically incapable of bypassing Data-Aegis
# when protection is enabled.
# ============================================================

DATA_AEGIS_URL = "http://localhost:5000"
groq_client = Groq()


def query_through_data_aegis(query, aegis_enabled=True):
    """
    Sends query through Data-Aegis middleware.
    Data-Aegis intercepts, classifies, masks, and returns clean data.
    The AI agent never touches the database directly.
    """
    try:
        response = requests.post(
            f"{DATA_AEGIS_URL}/query",
            json={
                "query": query,
                "aegis_enabled": aegis_enabled
            },
            timeout=30
        )

        return response.json(), response.status_code

    except requests.exceptions.ConnectionError:
        return {
            "error": "Data-Aegis server not running",
            "message": "Start the server with: python data_aegis_server.py"
        }, 503


def query_database_directly(query):
    """
    Bypasses Data-Aegis completely.
    Queries customer_db.json directly — raw sensitive data exposed.
    This simulates what happens WITHOUT middleware protection.
    """
    with open("customer_db.json", "r") as f:
        db = json.load(f)

    query_lower = query.lower()
    results = []

    for customer in db.get("customers", []):
        name_parts = customer["name"].lower().split()
        if any(part in query_lower for part in name_parts):
            results.append(customer)

    for employee in db.get("employees", []):
        if any(word in query_lower for word in ["employee", "staff", "credential", "key", "aws"]):
            results.append(employee)

    for record in db.get("healthcare_records", []):
        name_parts = record["name"].lower().split()
        if any(part in query_lower for part in name_parts):
            results.append(record)

    return results


def generate_ai_response(query, data, protected=True):
    """
    Generates AI response using provided data.
    When protected — data is already masked by Data-Aegis.
    When unprotected — data contains raw sensitive fields.
    """
    context = json.dumps(data, indent=2)

    if protected:
        system = """You are an enterprise AI assistant. 
        All sensitive data has been masked by Data-Aegis security middleware.
        Answer the user's question using only the sanitized data provided.
        Never reference masked fields directly.
        Keep response concise and professional."""
    else:
        system = """You are an enterprise AI assistant.
        Answer the user's question using the data provided.
        Be specific and include all details from the records."""

    response = groq_client.chat.completions.create(
        model="llama-3.3-70b-versatile",
        messages=[
            {"role": "system", "content": system},
            {"role": "user", "content": f"Question: {query}\n\nData:\n{context}"}
        ],
        temperature=0,
        max_tokens=400
    )

    return response.choices[0].message.content.strip()


def run_agent_query(query, aegis_enabled=True):
    """
    Main agent function — handles full query lifecycle.
    Shows clear before/after comparison of Data-Aegis protection.
    """
    print(f"\n{'='*60}")

    if aegis_enabled:
        print(f"  🔒 DATA-AEGIS ENABLED — Query intercepted")
        print(f"{'='*60}")
        print(f"  Query: '{query}'")
        print(f"  Routing through Data-Aegis middleware...\n")

        result, status_code = query_through_data_aegis(query, aegis_enabled=True)

        if status_code == 403:
            # Malicious query blocked
            incident = result.get("incident", {})
            print(f"  ⛔ QUERY BLOCKED BY DATA-AEGIS")
            print(f"  Incident: {incident.get('incident_id')}")
            print(f"  MITRE: {incident.get('mitre_technique_id')} — {incident.get('mitre_technique_name')}")
            print(f"  Severity: {incident.get('severity')}")
            print(f"  Escalated to: {incident.get('escalated_to')}")
            print(f"  Playbook: {incident.get('playbook')}")
            print(f"\n  🤖 AI Response: Access denied. This query has been flagged and escalated to the SOC team.")

        elif status_code == 200:
            detections = result.get("detections", [])
            records = result.get("records", [])

            if detections:
                print(f"  🚨 Sensitive data intercepted:")
                for detection in detections:
                    for field in detection.get("sensitive_fields", []):
                        print(f"     • {field['field']} → [{field['class']}] masked | MITRE: {field['mitre']}")
                print(f"\n  ✅ Clean data passed to AI agent\n")
            else:
                print(f"  ✅ No sensitive data detected — clean record\n")

            # Generate AI response using masked data
            clean_data = [r["data"] for r in records] if records else []
            if clean_data:
                ai_response = generate_ai_response(query, clean_data, protected=True)
                print(f"  🤖 AI Response (Data-Aegis Protected):")
                print(f"  {ai_response}")
            else:
                print(f"  🤖 AI Response: No records found matching your query.")

        else:
            print(f"  ❌ Error: {result.get('error', 'Unknown error')}")
            print(f"  {result.get('message', '')}")

    else:
        print(f"  ⚠️  DATA-AEGIS DISABLED — Direct database access")
        print(f"{'='*60}")
        print(f"  Query: '{query}'")
        print(f"  WARNING: No interception — raw sensitive data exposed\n")

        raw_records = query_database_directly(query)

        if raw_records:
            print(f"  🔓 Raw data returned (unprotected):")
            for record in raw_records:
                for key, value in record.items():
                    if key in ["ssn", "email", "aws_access_key", "aws_secret",
                               "date_of_birth", "diagnosis_code", "phone"]:
                        print(f"     ⚠️  {key}: {value} ← EXPOSED")

            ai_response = generate_ai_response(query, raw_records, protected=False)
            print(f"\n  🤖 AI Response (UNPROTECTED):")
            print(f"  {ai_response}")
        else:
            print(f"  No records found.")

    print(f"{'='*60}\n")


def main():
    print(f"""
╔══════════════════════════════════════════════════════════╗
║         DATA-AEGIS AI AGENT                              ║
║         Enterprise Query Interface                       ║
║                                                          ║
║  This agent demonstrates true middleware protection.     ║
║  Toggle Data-Aegis ON/OFF to see the difference.        ║
║                                                          ║
║  Commands:                                               ║
║  • Type any query naturally                              ║
║  • 'aegis off' — disable protection                      ║
║  • 'aegis on'  — enable protection                       ║
║  • 'exit'      — quit                                    ║
╚══════════════════════════════════════════════════════════╝
    """)

    aegis_enabled = True

    while True:
        status = "🔒 ON" if aegis_enabled else "⚠️  OFF"
        try:
            query = input(f"[Data-Aegis {status}] You: ").strip()

            if not query:
                continue

            if query.lower() == "exit":
                print("\n👋 Agent shutting down.\n")
                break

            elif query.lower() == "aegis off":
                aegis_enabled = False
                print("\n⚠️  Data-Aegis DISABLED — AI agent now has direct database access\n")

            elif query.lower() == "aegis on":
                aegis_enabled = True
                print("\n🔒 Data-Aegis ENABLED — All queries intercepted and protected\n")

            else:
                run_agent_query(query, aegis_enabled)

        except KeyboardInterrupt:
            print("\n\n👋 Agent shutting down.\n")
            break


if __name__ == "__main__":
    main()