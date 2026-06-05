import json
import time
import random
from datetime import datetime
from security_core import classify_log_entry
from app import apply_dynamic_masking

# ============================================================
# DATA-AEGIS AUTONOMOUS SECURITY AGENT
# Agentic SOC layer — continuously monitors enterprise data
# streams, makes autonomous remediation decisions, and
# generates incident tickets for high risk exposures.
# Mirrors Cyera's AI Guardian agentic workflow architecture.
# ============================================================

def generate_incident_ticket(row, security_meta):
    """
    Autonomously generates a structured incident ticket
    when the agent detects a high risk data exposure.
    Mirrors how a real SOC agentic workflow escalates threats.
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ticket = {
        "incident_id": f"INC-{random.randint(10000, 99999)}",
        "timestamp": timestamp,
        "severity": "CRITICAL" if security_meta["risk_score"] >= 8 else "HIGH",
        "source_record": row["ticket_id"],
        "source_system": row["source"],
        "region": row["region"],
        "data_class": security_meta["data_class"],
        "risk_score": security_meta["risk_score"],
        "description": security_meta["risk_reasoning"],
        "remediation_applied": security_meta["remediation_action"],
        "status": "AUTO_REMEDIATED",
        "assigned_to": "SOC_AGENT_01",
        "escalate_to_human": security_meta["risk_score"] >= 9
    }
    return ticket


def autonomous_decision(security_meta):
    """
    The agent's decision engine.
    Based on risk score it autonomously decides what action to take
    without human intervention — this is the agentic behavior.
    
    Risk Score 0-3:  Log and continue
    Risk Score 4-6:  Mask and log warning
    Risk Score 7-8:  Mask, generate incident ticket, alert SOC
    Risk Score 9-10: Mask, generate incident ticket, escalate to human
    """
    score = security_meta["risk_score"]
    
    if score <= 3:
        return "LOG_ONLY"
    elif score <= 6:
        return "MASK_AND_WARN"
    elif score <= 8:
        return "MASK_AND_TICKET"
    else:
        return "MASK_TICKET_ESCALATE"


def run_agent(database_rows, cycles=3):
    """
    The main agentic loop.
    Simulates continuous monitoring of an enterprise data stream.
    Each cycle represents the agent checking for new records —
    exactly how a real agentic SOC monitors cloud infrastructure.
    """
    
    print("\n" + "=" * 60)
    print("  DATA-AEGIS AUTONOMOUS SECURITY AGENT ONLINE")
    print("  Mode: Continuous Agentic SOC Monitoring")
    print("  Model: LLaMA 3.3 70B via Groq")
    print("  Status: ACTIVE")
    print("=" * 60 + "\n")
    
    all_incidents = []
    
    for cycle in range(1, cycles + 1):
        print(f"\n🔄 AGENT CYCLE {cycle}/{cycles} | {datetime.now().strftime('%H:%M:%S')}")
        print("   Scanning enterprise data stream for new records...\n")
        
        # Simulate agent picking up new records from the stream
        # In production this would be real CloudTrail events from SQS
        sampled_rows = random.sample(database_rows, k=min(3, len(database_rows)))
        
        for row in sampled_rows:
            log_content = row["service_log"]
            print(f"  📡 Agent intercepted: [{row['ticket_id']}] from {row['region']}")
            
            # Agent classifies the record autonomously
            security_meta = classify_log_entry(log_content)
            
            # Agent makes autonomous decision based on risk score
            decision = autonomous_decision(security_meta)
            
            if decision == "LOG_ONLY":
                print(f"  ✅ Risk Score: {security_meta['risk_score']}/10 | Decision: Log and continue")
                
            elif decision == "MASK_AND_WARN":
                sanitized = apply_dynamic_masking(log_content, security_meta["data_class"])
                print(f"  ⚠️  Risk Score: {security_meta['risk_score']}/10 | Decision: Masked | Class: {security_meta['data_class']}")
                
            elif decision == "MASK_AND_TICKET":
                sanitized = apply_dynamic_masking(log_content, security_meta["data_class"])
                ticket = generate_incident_ticket(row, security_meta)
                all_incidents.append(ticket)
                print(f"  🚨 Risk Score: {security_meta['risk_score']}/10 | Decision: Masked + Incident Generated")
                print(f"  🎫 Incident ID: {ticket['incident_id']} | Severity: {ticket['severity']}")
                
            elif decision == "MASK_TICKET_ESCALATE":
                sanitized = apply_dynamic_masking(log_content, security_meta["data_class"])
                ticket = generate_incident_ticket(row, security_meta)
                all_incidents.append(ticket)
                print(f"  🔴 Risk Score: {security_meta['risk_score']}/10 | Decision: Masked + Escalated to Human")
                print(f"  🎫 Incident ID: {ticket['incident_id']} | Severity: {ticket['severity']}")
                print(f"  👤 HUMAN ESCALATION REQUIRED — Assigned to: {ticket['assigned_to']}")
        
        if cycle < cycles:
            print(f"\n  ⏳ Agent sleeping 3 seconds before next cycle...")
            time.sleep(3)
    
    # Agent generates final incident report
    print("\n\n" + "=" * 60)
    print("  AGENT SESSION COMPLETE — INCIDENT REPORT")
    print("=" * 60)
    print(f"  Total Cycles Run:      {cycles}")
    print(f"  Incidents Generated:   {len(all_incidents)}")
    
    if all_incidents:
        print("\n  OPEN INCIDENTS:")
        for inc in all_incidents:
            escalation = "⚠️  ESCALATE TO HUMAN" if inc["escalate_to_human"] else "✅ Auto-remediated"
            print(f"\n  [{inc['incident_id']}] {inc['severity']} | {inc['data_class']}")
            print(f"  Region: {inc['region']} | Score: {inc['risk_score']}/10")
            print(f"  {escalation}")
    
    print("\n" + "=" * 60)
    print("  Agent shutting down. All incidents logged.")
    print("=" * 60 + "\n")
    
    return all_incidents


if __name__ == "__main__":
    with open("mock_db.json", "r") as f:
        database_rows = json.load(f)
    
    run_agent(database_rows, cycles=3)