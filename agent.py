import json
import time
import random
from datetime import datetime
from security_core import classify_log_entry
from app import apply_dynamic_masking

# ============================================================
# DATA-AEGIS AUTONOMOUS SECURITY AGENT v2
# True agentic SOC layer — maintains memory across cycles,
# detects threat patterns, autonomously escalates response,
# generates incident tickets, and persists audit trail.
# ============================================================

# Agent memory — persists across all cycles
agent_memory = {
    "seen_records": [],
    "region_threat_count": {},
    "user_threat_count": {},
    "repeated_threats": [],
    "total_incidents": 0,
    "cycle_summaries": []
}


def update_agent_memory(row, security_meta):
    """
    Updates agent memory after each record is processed.
    This is what makes it genuinely agentic — it builds
    a threat intelligence picture over time and changes
    behavior based on accumulated context.
    """
    region = row["region"]
    ticket_id = row["ticket_id"]

    # Track which records have been seen
    agent_memory["seen_records"].append(ticket_id)

    if security_meta["contains_sensitive_data"]:
        # Track threat frequency by region
        if region not in agent_memory["region_threat_count"]:
            agent_memory["region_threat_count"][region] = 0
        agent_memory["region_threat_count"][region] += 1

        # Flag regions with repeated threats
        if agent_memory["region_threat_count"][region] >= 2:
            if region not in agent_memory["repeated_threats"]:
                agent_memory["repeated_threats"].append(region)

        agent_memory["total_incidents"] += 1


def get_escalation_level(region, base_risk_score):
    """
    Agent intelligence layer — adjusts escalation based on
    accumulated threat memory. If a region has been flagged
    repeatedly the agent autonomously increases severity.
    This is genuine agentic behavior — decisions change
    based on accumulated context not just current input.
    """
    # Check if this region has repeated threats in memory
    if region in agent_memory["repeated_threats"]:
        escalated_score = min(base_risk_score + 2, 10)
        return escalated_score, True
    return base_risk_score, False


def confidence_threshold_decision(risk_score):
    """
    Confidence threshold engine.
    Prevents auto-remediation of borderline classifications.
    In security you don't want false positives causing
    unnecessary data loss — borderline cases go to human review.

    Score 0-3:  LOG_ONLY — low confidence threat
    Score 4-6:  HUMAN_REVIEW — borderline, don't auto-remediate
    Score 7-8:  AUTO_REMEDIATE — high confidence, act now
    Score 9-10: CRITICAL_ESCALATE — maximum severity
    """
    if risk_score <= 3:
        return "LOG_ONLY"
    elif risk_score <= 6:
        return "HUMAN_REVIEW"
    elif risk_score <= 8:
        return "AUTO_REMEDIATE"
    else:
        return "CRITICAL_ESCALATE"


def generate_incident_ticket(row, security_meta, escalated=False):
    """
    Generates structured incident ticket.
    Persisted to audit log for compliance and forensics.
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    return {
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
        "memory_escalated": escalated,
        "status": "AUTO_REMEDIATED",
        "assigned_to": "SOC_AGENT_01",
        "escalate_to_human": security_meta["risk_score"] >= 9
    }


def persist_incident_log(incidents):
    """
    Saves all incidents to immutable audit log.
    Critical for regulatory compliance and post-incident forensics.
    Every real SOC system maintains a persistent audit trail.
    """
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"incident_log_{timestamp}.json"

    audit_log = {
        "session_timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "total_incidents": len(incidents),
        "agent_memory_summary": {
            "regions_flagged": list(agent_memory["region_threat_count"].keys()),
            "repeat_threat_regions": agent_memory["repeated_threats"],
            "total_records_scanned": len(agent_memory["seen_records"])
        },
        "incidents": incidents
    }

    with open(filename, "w") as f:
        json.dump(audit_log, f, indent=2)

    return filename


def run_agent(database_rows, cycles=3):
    """
    Main agentic loop.
    Truly agentic because:
    1. Maintains memory across cycles
    2. Changes behavior based on threat patterns
    3. Autonomously escalates based on accumulated context
    4. Persists complete audit trail
    5. Applies confidence thresholds to prevent false positives
    """

    print("\n" + "=" * 60)
    print("  DATA-AEGIS AUTONOMOUS SECURITY AGENT v2 ONLINE")
    print("  Mode: Continuous Agentic SOC Monitoring")
    print("  Features: Memory | Confidence Thresholds | Audit Trail")
    print("  Status: ACTIVE")
    print("=" * 60 + "\n")

    all_incidents = []

    for cycle in range(1, cycles + 1):
        print(f"\n🔄 AGENT CYCLE {cycle}/{cycles} | {datetime.now().strftime('%H:%M:%S')}")
        print(f"   Memory: {len(agent_memory['seen_records'])} records seen | {len(agent_memory['repeated_threats'])} repeat-threat regions\n")

        sampled_rows = random.sample(database_rows, k=min(3, len(database_rows)))

        for row in sampled_rows:
            log_content = row["service_log"]
            print(f"  📡 Agent intercepted: [{row['ticket_id']}] from {row['region']}")

            security_meta = classify_log_entry(log_content)

            if not security_meta["contains_sensitive_data"]:
                print(f"  ✅ Risk Score: {security_meta['risk_score']}/10 | LOG_ONLY | {security_meta['risk_reasoning']}")
                update_agent_memory(row, security_meta)
                continue

            # Check agent memory for escalation
            adjusted_score, memory_escalated = get_escalation_level(
                row["region"],
                security_meta["risk_score"]
            )

            if memory_escalated:
                security_meta["risk_score"] = adjusted_score
                print(f"  🧠 MEMORY ESCALATION | Region {row['region']} flagged repeatedly | Score boosted to {adjusted_score}/10")

            # Apply confidence threshold decision
            decision = confidence_threshold_decision(security_meta["risk_score"])

            if decision == "LOG_ONLY":
                print(f"  ✅ Risk Score: {security_meta['risk_score']}/10 | LOW CONFIDENCE | Logged only")

            elif decision == "HUMAN_REVIEW":
                print(f"  ⚠️  Risk Score: {security_meta['risk_score']}/10 | BORDERLINE | Sent to human review")
                print(f"  👤 Class: {security_meta['data_class']} | Auto-remediation withheld — confidence too low")

            elif decision == "AUTO_REMEDIATE":
                sanitized = apply_dynamic_masking(log_content, security_meta["data_class"])
                ticket = generate_incident_ticket(row, security_meta, memory_escalated)
                all_incidents.append(ticket)
                print(f"  🚨 Risk Score: {security_meta['risk_score']}/10 | AUTO_REMEDIATED | Class: {security_meta['data_class']}")
                print(f"  🎫 Incident: {ticket['incident_id']} | Severity: {ticket['severity']}")

            elif decision == "CRITICAL_ESCALATE":
                sanitized = apply_dynamic_masking(log_content, security_meta["data_class"])
                ticket = generate_incident_ticket(row, security_meta, memory_escalated)
                all_incidents.append(ticket)
                print(f"  🔴 Risk Score: {security_meta['risk_score']}/10 | CRITICAL | Class: {security_meta['data_class']}")
                print(f"  🎫 Incident: {ticket['incident_id']} | Severity: {ticket['severity']}")
                print(f"  👤 HUMAN ESCALATION REQUIRED — Assigned to: {ticket['assigned_to']}")

            update_agent_memory(row, security_meta)

        # Cycle summary
        agent_memory["cycle_summaries"].append({
            "cycle": cycle,
            "records_processed": len(sampled_rows),
            "incidents_this_cycle": len([i for i in all_incidents if i])
        })

        if cycle < cycles:
            print(f"\n  ⏳ Agent sleeping 3 seconds | Memory state preserved...")
            time.sleep(3)

    # Persist audit log
    log_file = persist_incident_log(all_incidents)

    # Final report
    print("\n\n" + "=" * 60)
    print("  AGENT SESSION COMPLETE — FINAL REPORT")
    print("=" * 60)
    print(f"  Total Cycles Run:          {cycles}")
    print(f"  Total Records Scanned:     {len(agent_memory['seen_records'])}")
    print(f"  Total Incidents Generated: {len(all_incidents)}")
    print(f"  Repeat Threat Regions:     {agent_memory['repeated_threats'] or 'None'}")
    print(f"  Audit Log Saved:           {log_file}")

    if all_incidents:
        print("\n  OPEN INCIDENTS:")
        for inc in all_incidents:
            memory_flag = " | 🧠 MEMORY ESCALATED" if inc["memory_escalated"] else ""
            escalation = "⚠️  ESCALATE TO HUMAN" if inc["escalate_to_human"] else "✅ Auto-remediated"
            print(f"\n  [{inc['incident_id']}] {inc['severity']} | {inc['data_class']}")
            print(f"  Region: {inc['region']} | Score: {inc['risk_score']}/10{memory_flag}")
            print(f"  {escalation}")

    print("\n" + "=" * 60)
    print("  Agent shutting down. Audit trail persisted.")
    print("=" * 60 + "\n")

    return all_incidents


if __name__ == "__main__":
    with open("mock_db.json", "r") as f:
        database_rows = json.load(f)

    run_agent(database_rows, cycles=3)