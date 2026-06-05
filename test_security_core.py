import unittest
from app import apply_dynamic_masking

class TestDataAegisMasking(unittest.TestCase):
    """
    Unit tests for Data-Aegis dynamic masking engine.
    
    These tests verify that the remediation layer correctly
    masks sensitive data for each classification type.
    Critical — if masking fails silently it's a data breach.
    """

    def test_aws_credential_redacted(self):
        """AWS access keys must be fully redacted"""
        text = "Temporary master AWS access key used: AKIAIOSFODNN7EXAMPLE in production"
        result = apply_dynamic_masking(text, "Credentials")
        self.assertIn("[REDACTED_AWS_CREDENTIAL]", result)
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", result)

    def test_ssn_redacted(self):
        """SSNs must be fully redacted from PII records"""
        text = "Customer SSN: 000-12-3456 on file"
        result = apply_dynamic_masking(text, "PII")
        self.assertIn("[REDACTED_NATIONAL_ID]", result)
        self.assertNotIn("000-12-3456", result)

    def test_email_redacted(self):
        """Email addresses must be fully redacted from PII records"""
        text = "Contact email: john.doe@gmail.com for follow up"
        result = apply_dynamic_masking(text, "PII")
        self.assertIn("[REDACTED_EMAIL]", result)
        self.assertNotIn("john.doe@gmail.com", result)

    def test_patient_id_redacted(self):
        """Patient IDs must be redacted from healthcare records"""
        text = "Patient ID 78432 admitted for treatment"
        result = apply_dynamic_masking(text, "Healthcare")
        self.assertIn("[REDACTED_PATIENT_ID]", result)
        self.assertNotIn("78432", result)

    def test_iam_violation_flagged(self):
        """IAM violations must be flagged for human review not masked"""
        text = "IAM role policy updated without change ticket"
        result = apply_dynamic_masking(text, "IAM_Violation")
        self.assertIn("IAM_VIOLATION_FLAGGED_FOR_REVIEW", result)

    def test_clean_record_unchanged(self):
        """Clean records must pass through completely unmodified"""
        text = "Standard S3 bucket read operation completed successfully"
        result = apply_dynamic_masking(text, "None")
        self.assertEqual(result, text)


if __name__ == "__main__":
    unittest.main()