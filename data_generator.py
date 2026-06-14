import json
import random
from datetime import datetime, timedelta

# ============================================================
# DATA-AEGIS SYNTHETIC LOG GENERATOR
# Generates realistic AWS CloudTrail log streams dynamically.
# Every run produces genuinely new records — simulates real
# enterprise data volume for continuous agent monitoring.
# Covers 3 log sources: CloudTrail, GuardDuty, S3 Access Logs
#
# PRODUCTION NOTE: In a live deployment this generator is
# replaced by real CloudTrail events consumed from AWS SQS.
# Timestamp distribution is weighted 70% business hours /
# 30% after-hours to mirror real enterprise activity patterns.
# ============================================================

# Realistic AWS data pools
AWS_REGIONS = ["us-east-1", "us-west-2", "eu-west-1", "us-east-2", "ap-southeast-1"]
AWS_ACCOUNTS = ["123456789012", "987654321098", "456789012345"]
AWS_USERS = [
    "arn:aws:iam::123456789012:user/john.smith",
    "arn:aws:iam::123456789012:user/dev.ops",
    "arn:aws:iam::123456789012:user/contractor.ext",
    "arn:aws:iam::123456789012:user/admin.user",
    "arn:aws:iam::123456789012:user/billing.agent"
]

# Sensitive data pools for realistic PII generation
FIRST_NAMES = ["John", "Sarah", "Michael", "Emily", "David", "Jessica"]
LAST_NAMES = ["Smith", "Johnson", "Williams", "Brown", "Jones", "Davis"]
DIAGNOSIS_CODES = ["E11.9", "I10", "J45.909", "M54.5", "F32.9"]
DIAGNOSIS_NAMES = ["Type 2 Diabetes", "Hypertension", "Asthma", "Back Pain", "Depression"]


def random_timestamp():
    """
    Generates realistic CloudTrail timestamps.
    Weighted 70% business hours / 30% after-hours to mirror
    real enterprise activity patterns — most legitimate activity
    occurs during business hours with occasional after-hours events
    that warrant closer inspection.
    
    In production deployment this generator is replaced by real
    CloudTrail events consumed from AWS SQS queue. The detection
    logic in anomaly_detector.py is production-ready and operates
    identically on real CloudTrail timestamps.
    """
    base = datetime.now() - timedelta(hours=random.randint(0, 24))
    
    if random.random() < 0.7:
        # 70% chance — business hours 9am to 6pm
        hour = random.randint(9, 17)
        base = base.replace(hour=hour)
    # 30% chance — random hour including after-hours
    
    return base.strftime("%Y-%m-%dT%H:%M:%SZ")


def random_ip():
    """Generates a realistic source IP"""
    return f"{random.randint(100,200)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"


def generate_cloudtrail_clean():
    """Generates a clean CloudTrail record with no sensitive data"""
    events = [
        ("ListBuckets", "s3.amazonaws.com", "Standard S3 bucket listing operation. No sensitive data accessed."),
        ("DescribeInstances", "ec2.amazonaws.com", "EC2 instance metadata query. Routine infrastructure check."),
        ("GetObject", "s3.amazonaws.com", "Public asset retrieved from CDN bucket. No user data involved."),
        ("DeleteObject", "s3.amazonaws.com", f"Automated Lambda cleanup removed {random.randint(50,200)} expired temp files."),
    ]
    event_name, source, log = random.choice(events)
    region = random.choice(AWS_REGIONS)

    return {
        "ticket_id": f"T-{random.randint(1000, 9999)}",
        "eventVersion": "1.08",
        "userIdentity": {
            "type": "IAMUser",
            "arn": random.choice(AWS_USERS),
            "accountId": random.choice(AWS_ACCOUNTS)
        },
        "eventTime": random_timestamp(),
        "eventSource": source,
        "eventName": event_name,
        "awsRegion": region,
        "sourceIPAddress": random_ip(),
        "source": "AWS_CloudTrail",
        "region": region,
        "service_log": log,
        "classification_context": "Cloud Operations"
    }


def generate_cloudtrail_credentials():
    """Generates a CloudTrail record with exposed AWS credentials"""
    key = f"AKIA{''.join(random.choices('ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', k=16))}"
    region = random.choice(AWS_REGIONS)

    return {
        "ticket_id": f"T-{random.randint(1000, 9999)}",
        "eventVersion": "1.08",
        "userIdentity": {
            "type": "IAMUser",
            "arn": random.choice(AWS_USERS),
            "accountId": random.choice(AWS_ACCOUNTS)
        },
        "eventTime": random_timestamp(),
        "eventSource": "rds.amazonaws.com",
        "eventName": "ModifyDBInstance",
        "awsRegion": region,
        "sourceIPAddress": random_ip(),
        "source": "AWS_CloudTrail",
        "region": region,
        "service_log": f"Urgent migration issue. Temporary master AWS access key used: {key}. Developer resolving database timeout on RDS instance.",
        "classification_context": "Cloud Infrastructure"
    }


def generate_cloudtrail_pii():
    """Generates a CloudTrail record with exposed PII"""
    first = random.choice(FIRST_NAMES)
    last = random.choice(LAST_NAMES)
    ssn = f"{random.randint(100,999)}-{random.randint(10,99)}-{random.randint(1000,9999)}"
    email = f"{first.lower()}.{last.lower()}@{random.choice(['gmail.com', 'yahoo.com', 'outlook.com'])}"
    amount = random.randint(100, 5000)
    region = random.choice(AWS_REGIONS)

    return {
        "ticket_id": f"T-{random.randint(1000, 9999)}",
        "eventVersion": "1.08",
        "userIdentity": {
            "type": "IAMUser",
            "arn": random.choice(AWS_USERS),
            "accountId": random.choice(AWS_ACCOUNTS)
        },
        "eventTime": random_timestamp(),
        "eventSource": "s3.amazonaws.com",
        "eventName": "GetObject",
        "awsRegion": region,
        "sourceIPAddress": random_ip(),
        "source": "AWS_CloudTrail",
        "region": region,
        "service_log": f"Customer {first} {last} (SSN: {ssn}, Email: {email}) disputed billing charge of ${amount}. Case opened in Salesforce CRM.",
        "classification_context": "Billing Finance"
    }


def generate_cloudtrail_healthcare():
    """Generates a CloudTrail record with exposed healthcare data"""
    patient_id = random.randint(10000, 99999)
    dob = f"{random.randint(1,12):02d}/{random.randint(1,28):02d}/{random.randint(1950,2000)}"
    idx = random.randint(0, len(DIAGNOSIS_CODES)-1)
    code = DIAGNOSIS_CODES[idx]
    name = DIAGNOSIS_NAMES[idx]
    region = random.choice(AWS_REGIONS)

    return {
        "ticket_id": f"T-{random.randint(1000, 9999)}",
        "eventVersion": "1.08",
        "userIdentity": {
            "type": "IAMUser",
            "arn": "arn:aws:iam::123456789012:user/contractor.ext",
            "accountId": random.choice(AWS_ACCOUNTS)
        },
        "eventTime": random_timestamp(),
        "eventSource": "s3.amazonaws.com",
        "eventName": "GetObject",
        "awsRegion": region,
        "sourceIPAddress": random_ip(),
        "source": "AWS_CloudTrail",
        "region": region,
        "service_log": f"Healthcare record accessed: Patient ID {patient_id}, DOB {dob}, Diagnosis Code ICD-10 {code} ({name}). Accessed by external contractor account.",
        "classification_context": "Healthcare Compliance"
    }


def generate_cloudtrail_iam():
    """Generates a CloudTrail record with IAM violation"""
    policies = ["AmazonS3FullAccess", "AdministratorAccess", "AmazonEC2FullAccess"]
    policy = random.choice(policies)
    region = random.choice(AWS_REGIONS)

    return {
        "ticket_id": f"T-{random.randint(1000, 9999)}",
        "eventVersion": "1.08",
        "userIdentity": {
            "type": "IAMUser",
            "arn": "arn:aws:iam::123456789012:user/admin.user",
            "accountId": random.choice(AWS_ACCOUNTS)
        },
        "eventTime": random_timestamp(),
        "eventSource": "iam.amazonaws.com",
        "eventName": "PutRolePolicy",
        "awsRegion": region,
        "sourceIPAddress": random_ip(),
        "source": "AWS_CloudTrail",
        "region": region,
        "service_log": f"IAM role policy updated for service account svc-data-pipeline. Added {policy} permissions by admin user. Change ticket not found.",
        "classification_context": "IAM Security"
    }


def generate_guardduty_finding():
    """Generates a GuardDuty threat finding"""
    findings = [
        "UnauthorizedAccess:IAMUser/TorIPCaller — API call from known Tor exit node detected.",
        "Recon:IAMUser/UserPermissions — Unusual enumeration of IAM permissions by existing user.",
        "CryptoCurrency:EC2/BitcoinTool.B — EC2 instance querying IP associated with cryptocurrency activity.",
        "Trojan:EC2/BlackholeTraffic — EC2 instance communicating with known blackhole IP address."
    ]
    region = random.choice(AWS_REGIONS)

    return {
        "ticket_id": f"T-{random.randint(1000, 9999)}",
        "eventVersion": "1.08",
        "userIdentity": {
            "type": "IAMUser",
            "arn": random.choice(AWS_USERS),
            "accountId": random.choice(AWS_ACCOUNTS)
        },
        "eventTime": random_timestamp(),
        "eventSource": "guardduty.amazonaws.com",
        "eventName": "GuardDutyFinding",
        "awsRegion": region,
        "sourceIPAddress": random_ip(),
        "source": "AWS_GuardDuty",
        "region": region,
        "service_log": random.choice(findings),
        "classification_context": "Threat Intelligence"
    }


def generate_s3_access_log():
    """Generates an S3 access log entry"""
    buckets = ["enterprise-customer-data", "prod-financial-records", "backup-healthcare-archive"]
    bucket = random.choice(buckets)
    first = random.choice(FIRST_NAMES)
    last = random.choice(LAST_NAMES)
    region = random.choice(AWS_REGIONS)

    logs = [
        f"GET request to s3://{bucket}/public/assets/logo.png — 200 OK. Standard asset retrieval.",
        f"PUT request to s3://{bucket}/customer-records/{first.lower()}_{last.lower()}_profile.json — 200 OK. Customer profile updated.",
        f"DELETE request to s3://{bucket}/temp/expired_session_tokens/ — 204 No Content. Automated cleanup.",
    ]

    return {
        "ticket_id": f"T-{random.randint(1000, 9999)}",
        "eventVersion": "1.08",
        "userIdentity": {
            "type": "IAMUser",
            "arn": random.choice(AWS_USERS),
            "accountId": random.choice(AWS_ACCOUNTS)
        },
        "eventTime": random_timestamp(),
        "eventSource": "s3.amazonaws.com",
        "eventName": "S3AccessLog",
        "awsRegion": region,
        "sourceIPAddress": random_ip(),
        "source": "AWS_S3_AccessLog",
        "region": region,
        "service_log": random.choice(logs),
        "classification_context": "Storage Operations"
    }


def generate_live_stream(num_records=5):
    """
    Generates a mixed batch of realistic log records
    across all three AWS sources — CloudTrail, GuardDuty, S3.
    Weighted so roughly 60% clean, 40% suspicious — 
    mirrors real enterprise threat rates.
    """
    generators = [
        # Clean records — higher weight
        generate_cloudtrail_clean,
        generate_cloudtrail_clean,
        generate_cloudtrail_clean,
        generate_s3_access_log,
        generate_s3_access_log,
        # Suspicious records
        generate_cloudtrail_credentials,
        generate_cloudtrail_pii,
        generate_cloudtrail_healthcare,
        generate_cloudtrail_iam,
        generate_guardduty_finding,
    ]

    return [random.choice(generators)() for _ in range(num_records)]


if __name__ == "__main__":
    print("🔄 Generating synthetic enterprise log stream...\n")
    records = generate_live_stream(10)
    print(json.dumps(records, indent=2))
    print(f"\n✅ Generated {len(records)} synthetic log records across CloudTrail, GuardDuty, and S3")