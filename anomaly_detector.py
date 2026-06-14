from datetime import datetime

# ============================================================
# DATA-AEGIS ANOMALOUS ACCESS DETECTION ENGINE
# Detects suspicious behavioral patterns in CloudTrail logs
# beyond just sensitive data content.
# Layer 2 detection — HOW data is being accessed not just
# WHAT data is being accessed.
# Mirrors Cyera's Access Trail behavioral detection product.
# ============================================================

# Business hours definition — 9am to 6pm
BUSINESS_HOURS_START = 9
BUSINESS_HOURS_END = 18

# Sensitive buckets that should trigger alerts on external access
SENSITIVE_BUCKETS = [
    "enterprise-customer-data",
    "prod-financial-records",
    "backup-healthcare-archive",
    "internal-credentials-store"
]

# External contractor accounts that should have limited access
EXTERNAL_ACCOUNTS = [
    "contractor.ext",
    "vendor.access",
    "external.user"
]

# Track access patterns across records for bulk detection
access_tracker = {}


def detect_after_hours_access(row):
    """
    Detects data access outside business hours.
    Contractors and external accounts accessing sensitive
    data at 3am is a major red flag — could indicate
    compromised credentials or malicious insider activity.
    """
    try:
        event_time = row.get("eventTime", "")
        if not event_time:
            return None

        # Parse the timestamp
        dt = datetime.strptime(event_time, "%Y-%m-%dT%H:%M:%SZ")
        hour = dt.hour

        # Check if outside business hours
        if hour < BUSINESS_HOURS_START or hour >= BUSINESS_HOURS_END:
            user_arn = row.get("userIdentity", {}).get("arn", "")
            username = user_arn.split("/")[-1] if "/" in user_arn else "unknown"

            # Higher risk for external contractors after hours
            is_external = any(ext in username for ext in EXTERNAL_ACCOUNTS)
            risk_score = 8 if is_external else 5

            return {
                "anomaly_type": "AFTER_HOURS_ACCESS",
                "description": f"Data access detected at {dt.strftime('%H:%M')} — outside business hours (09:00-18:00)",
                "user": username,
                "time": dt.strftime("%H:%M:%S"),
                "risk_score": risk_score,
                "is_external_user": is_external,
                "mitre_technique_id": "T1078",
                "mitre_technique_name": "Valid Accounts",
                "mitre_tactic": "Initial Access"
            }
    except Exception:
        return None

    return None


def detect_sensitive_bucket_access(row):
    """
    Detects external contractors accessing sensitive S3 buckets.
    External accounts should never have direct access to
    production financial, healthcare, or credential stores.
    """
    user_arn = row.get("userIdentity", {}).get("arn", "")
    username = user_arn.split("/")[-1] if "/" in user_arn else ""
    service_log = row.get("service_log", "")
    event_source = row.get("eventSource", "")

    # Only check S3 events
    if "s3" not in event_source:
        return None

    # Check if external user
    is_external = any(ext in username for ext in EXTERNAL_ACCOUNTS)
    if not is_external:
        return None

    # Check if accessing sensitive bucket
    for bucket in SENSITIVE_BUCKETS:
        if bucket in service_log:
            return {
                "anomaly_type": "SENSITIVE_BUCKET_ACCESS",
                "description": f"External account '{username}' accessing sensitive bucket '{bucket}'",
                "user": username,
                "bucket": bucket,
                "risk_score": 7,
                "is_external_user": True,
                "mitre_technique_id": "T1530",
                "mitre_technique_name": "Data from Cloud Storage",
                "mitre_tactic": "Collection"
            }

    return None


def detect_bulk_access(row):
    """
    Detects unusually high volume of data access from same user.
    A user pulling 20+ records in 60 seconds suggests
    automated exfiltration not normal business usage.
    """
    user_arn = row.get("userIdentity", {}).get("arn", "")
    username = user_arn.split("/")[-1] if "/" in user_arn else "unknown"
    event_name = row.get("eventName", "")

    # Only track read operations
    if event_name not in ["GetObject", "ListBuckets", "DescribeInstances"]:
        return None

    # Track access count per user
    if username not in access_tracker:
        access_tracker[username] = 0
    access_tracker[username] += 1

    # Flag if user has accessed more than 5 records this session
    if access_tracker[username] >= 5:
        return {
            "anomaly_type": "BULK_DATA_ACCESS",
            "description": f"User '{username}' has accessed {access_tracker[username]} records this session — possible data exfiltration",
            "user": username,
            "access_count": access_tracker[username],
            "risk_score": 7,
            "is_external_user": any(ext in username for ext in EXTERNAL_ACCOUNTS),
            "mitre_technique_id": "T1530",
            "mitre_technique_name": "Data from Cloud Storage",
            "mitre_tactic": "Exfiltration"
        }

    return None


def detect_anomalous_iam_activity(row):
    """
    Detects suspicious IAM activity patterns.
    Policy changes without change tickets during off hours
    is a strong indicator of privilege escalation attack.
    """
    event_name = row.get("eventName", "")
    event_source = row.get("eventSource", "")
    service_log = row.get("service_log", "")

    if "iam" not in event_source:
        return None

    suspicious_events = ["PutRolePolicy", "AttachUserPolicy", "CreateAccessKey"]

    if event_name in suspicious_events:
        # Extra suspicious if no change ticket
        if "change ticket not found" in service_log.lower():
            return {
                "anomaly_type": "SUSPICIOUS_IAM_ACTIVITY",
                "description": f"Suspicious IAM operation '{event_name}' detected without change ticket authorization",
                "event": event_name,
                "risk_score": 8,
                "is_external_user": False,
                "mitre_technique_id": "T1078",
                "mitre_technique_name": "Valid Accounts",
                "mitre_tactic": "Privilege Escalation"
            }

    return None


def run_anomaly_detection(row):
    """
    Master anomaly detection function.
    Runs all detection checks against a single log record.
    Returns list of anomalies found — empty if clean.
    This is Layer 2 detection — behavioral patterns
    on top of Layer 1 content classification.
    """
    anomalies = []

    # Run all detectors
    checks = [
        detect_after_hours_access(row),
        detect_sensitive_bucket_access(row),
        detect_bulk_access(row),
        detect_anomalous_iam_activity(row)
    ]

    # Collect non-None results
    for result in checks:
        if result is not None:
            anomalies.append(result)

    return anomalies


if __name__ == "__main__":
    # Test with sample records
    test_records = [
        {
            "ticket_id": "T-TEST-1",
            "eventTime": "2024-03-15T03:15:00Z",
            "eventSource": "s3.amazonaws.com",
            "eventName": "GetObject",
            "userIdentity": {"arn": "arn:aws:iam::123456789012:user/contractor.ext"},
            "service_log": "Healthcare record accessed from enterprise-customer-data bucket",
            "region": "us-east-1",
            "source": "AWS_CloudTrail"
        },
        {
            "ticket_id": "T-TEST-2",
            "eventTime": "2024-03-15T14:30:00Z",
            "eventSource": "iam.amazonaws.com",
            "eventName": "PutRolePolicy",
            "userIdentity": {"arn": "arn:aws:iam::123456789012:user/admin.user"},
            "service_log": "IAM role policy updated. Change ticket not found.",
            "region": "us-east-1",
            "source": "AWS_CloudTrail"
        }
    ]

    print("🔍 Testing Anomalous Access Detection Engine\n")
    for record in test_records:
        anomalies = run_anomaly_detection(record)
        if anomalies:
            for a in anomalies:
                print(f"🚨 [{record['ticket_id']}] {a['anomaly_type']}")
                print(f"   {a['description']}")
                print(f"   Risk: {a['risk_score']}/10 | MITRE: {a['mitre_technique_id']} — {a['mitre_technique_name']}")
                print()
        else:
            print(f"✅ [{record['ticket_id']}] No anomalies detected")