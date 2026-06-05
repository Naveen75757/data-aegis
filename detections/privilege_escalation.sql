-- ============================================================
-- Data-Aegis Detection Query: Unauthorized Privilege Escalation
-- ============================================================
-- Target: Identify IAM Policy Attachments granting Administrative 
-- or Full S3 privileges without a corresponding authorized 
-- IT service change ticket.
--
-- Compatible with: AWS Athena, Snowflake, BigQuery
-- Log Source: AWS CloudTrail via S3 Log Archive
-- Severity: HIGH
-- MITRE ATT&CK: T1078 - Valid Accounts, T1548 - Abuse Elevation
-- ============================================================

SELECT 
    eventTime,
    userIdentity.arn                    AS actor_arn,
    userIdentity.type                   AS identity_type,
    requestParameters.policyArn         AS attached_policy,
    recipientAccountId                  AS aws_account_id,
    awsRegion                           AS region,
    sourceIPAddress                     AS source_ip,
    'UNAUTHORIZED_PRIVILEGE_ESCALATION' AS detection_type,
    'HIGH'                              AS severity

FROM 
    aws_cloudtrail_logs

WHERE 
    -- Catch all policy attachment events
    eventName IN (
        'AttachUserPolicy',
        'AttachGroupPolicy', 
        'AttachRolePolicy',
        'PutRolePolicy'
    )
    
    -- Flag full access or admin policies specifically
    AND (
        requestParameters.policyArn LIKE '%AmazonS3FullAccess%'
        OR requestParameters.policyArn LIKE '%AdministratorAccess%'
        OR requestParameters.policyArn LIKE '%FullAccess%'
    )
    
    -- Only look at recent events - last 1 hour
    AND eventTime >= DATE_SUB(NOW(), INTERVAL 1 HOUR)
    
    -- Exclude known automated service accounts
    AND userIdentity.arn NOT LIKE '%AWSServiceRole%'

ORDER BY 
    eventTime DESC;

-- ============================================================
-- Expected Output: Any results here represent a HIGH severity
-- finding that should be immediately routed to the Data-Aegis
-- autonomous agent for contextual classification and remediation.
-- ============================================================