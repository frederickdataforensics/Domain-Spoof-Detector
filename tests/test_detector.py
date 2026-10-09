import unittest
from pathlib import Path
from unittest.mock import patch
from app import create_app
from idnHomoglyphDetector import (
    analyze,
    defang_hostname,
    sanitized_defanged_display,
)

PHISHTANK_FIXTURE_PATH = (
    Path(__file__).parent
    / "fixtures"
    / "phishtank_sample.json"
)

class DetectorTests(unittest.TestCase):
    def test_ascii_lookalike(self):
        report = analyze("paypa1.com", ["paypal.com"])
        reasons = {finding.reason for finding in report.findings}
        self.assertIn("ASCII look-alike substitution", reasons)

    def test_unicode_homograph(self):
        report = analyze("pаypal.com", ["paypal.com"])
        self.assertIn("Cyrillic", report.scripts)
        self.assertGreater(report.risk_score, 0)

    def test_punycode_finding_is_not_duplicated(self):
        report = analyze("xn--pypal-4ve.com", ["paypal.com"])
        punycode_findings = [
            finding for finding in report.findings
            if finding.reason == "Punycode label"
        ]
        self.assertEqual(len(punycode_findings), 1)

    def test_url_hostname_extraction_does_not_display_path(self):
        app = create_app()
        app.testing = True
        response = app.test_client().post(
            "/analyze",
            data={
                "value": "https://example.com/private?token=secret",
                "trusted": "",
                "acknowledged": "yes",
            },
        )
        body = response.get_data(as_text=True)
        self.assertEqual(response.status_code, 200)
        self.assertNotIn("token=secret", body)
        self.assertNotIn("/private", body)

    def test_acknowledgment_required(self):
        app = create_app()
        app.testing = True
        response = app.test_client().post(
            "/analyze", data={"value": "example.com"}
        )
        self.assertEqual(response.status_code, 400)

    def test_health_reports_full_unicode_dataset(self):
        app = create_app()
        app.testing = True
        response = app.test_client().get("/health")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["confusables_version"], "17.0.0")

    def test_result_explains_scope_without_comparison_domain(self):
        app = create_app()
        app.testing = True

        response = app.test_client().post(
            "/analyze",
            data={
                "value": "example.com",
                "trusted": "",
                "acknowledged": "yes",
            },
        )

        body = response.get_data(as_text=True)

        self.assertEqual(response.status_code, 200)
        self.assertIn("Domain-name indicator score", body)
        self.assertIn(
            "No expected website was supplied",
            body,
        )
        self.assertIn(
            "not a percentage probability of phishing",
            body,
        )

    def test_result_identifies_comparison_domain(self):
        app = create_app()
        app.testing = True

        response = app.test_client().post(
            "/analyze",
            data={
                "value": "paypaI.com",
                "trusted": "paypal.com",
                "acknowledged": "yes",
            },
        )

        body = response.get_data(as_text=True)

        self.assertEqual(response.status_code, 200)
        self.assertIn("paypal[.]com", body)
        self.assertIn(
            "We found character or spelling warning signs",
            body,
        )


    def test_defang_hostname(self):
        result = defang_hostname("login.example.com")

        self.assertEqual(result, "login[.]example[.]com")

    def test_sanitized_defanged_display_removes_sensitive_url_parts(self):
        submitted_value = (
            "https://user:password@example.com/private/document"
            "?token=secret-value#account"
        )

        result = sanitized_defanged_display(submitted_value)

        self.assertEqual(result, "example[.]com")
        self.assertNotIn("user", result)
        self.assertNotIn("password", result)
        self.assertNotIn("private", result)
        self.assertNotIn("document", result)
        self.assertNotIn("token", result)
        self.assertNotIn("secret-value", result)
        self.assertNotIn("account", result)

    def test_sanitized_defanged_display_accepts_bare_domain(self):
        result = sanitized_defanged_display("subdomain.example.com")

        self.assertEqual(result, "subdomain[.]example[.]com")


    def test_web_result_displays_only_sanitized_defanged_hostname(self):
        app = create_app()
        app.testing = True

        response = app.test_client().post(
            "/analyze",
            data={
                "value": (
                    "https://user:password@example.com/private/document"
                    "?token=secret-value#account"
                ),
                "trusted": "",
                "acknowledged": "yes",
            },
        
        )
        body = response.get_data(as_text=True)

        self.assertEqual(response.status_code, 200)
        self.assertIn("example[.]com", body)
        self.assertIn("Submitted domain, displayed safely", body)
        self.assertNotIn("user:password", body)
        self.assertNotIn("/private/document", body)
        self.assertNotIn("token=secret-value", body)
        self.assertNotIn("#account", body)

    
    def test_fabricated_intelligence_is_hidden_when_disabled(self):
        app = create_app()
        app.testing = True
        app.config["FABRICATED_THREAT_LOOKUP_ENABLED"] = False

        response = app.test_client().post(
            "/analyze",
            data={
                "value": (
                    "https://login-alert.example.test/"
                    "account/verify"
                ),
                "trusted": "",
                "acknowledged": "yes",
            },
        )

        body = response.get_data(as_text=True)

        self.assertEqual(response.status_code, 200)
        self.assertNotIn("Known-Threat Intelligence", body)
        self.assertNotIn("FDF Fabricated Test Feed", body)
        self.assertNotIn("test-phish-1001", body)

    def test_fabricated_intelligence_renders_when_enabled(self):
        app = create_app()
        app.testing = True
        app.config["FABRICATED_THREAT_LOOKUP_ENABLED"] = True

        response = app.test_client().post(
            "/analyze",
            data={
                "value": (
                    "https://login-alert.example.test/"
                    "account/verify"
                ),
                "trusted": "",
                "acknowledged": "yes",
            },
        )

        body = response.get_data(as_text=True)

        self.assertEqual(response.status_code, 200)
        self.assertIn("Known-Threat Intelligence", body)
        self.assertIn("Development test data", body)
        self.assertIn("FDF Fabricated Test Feed", body)
        self.assertIn("Phishing", body)
        self.assertIn("Exact Url", body)
        self.assertIn("Verified", body)
        self.assertIn("test-phish-1001", body)

    def test_no_match_intelligence_result_does_not_claim_safety(self):
        app = create_app()
        app.testing = True
        app.config["FABRICATED_THREAT_LOOKUP_ENABLED"] = True

        response = app.test_client().post(
            "/analyze",
            data={
                "value": "https://clean.example.test/",
                "trusted": "",
                "acknowledged": "yes",
            },
        )

        body = response.get_data(as_text=True)

        self.assertEqual(response.status_code, 200)
        self.assertIn("No matching threat records found", body)
        self.assertIn(
            "It does not mean the domain or URL is",
            body,
        )
        self.assertNotIn("confirmed safe", body.casefold())
        

    def test_web_result_uses_configured_phishtank_feed(self):
        with patch.dict(
            "os.environ",
            {
                "FDF_PHISHTANK_FEED_PATH": str(
                    PHISHTANK_FIXTURE_PATH
                )
            },
            clear=False,
        ):
            app = create_app()

        app.testing = True

        response = app.test_client().post(
            "/analyze",
            data={
                "value": (
                    "https://login-alert.example.test/"
                    "account?source=email"
                ),
                "trusted": "",
                "acknowledged": "yes",
            },
        )

        body = response.get_data(as_text=True)

        self.assertEqual(response.status_code, 200)
        self.assertIn("PhishTank", body)
        self.assertIn(
            "exactly matches a verified",
            body,
        )

    def test_missing_configured_feed_reports_unavailable(self):
        with patch.dict(
            "os.environ",
            {
                "FDF_PHISHTANK_FEED_PATH": (
                    "/missing/phishtank-feed.json"
                )
            },
            clear=False,
        ):
            app = create_app()

        app.testing = True

        response = app.test_client().post(
            "/analyze",
            data={
                "value": "https://example.test/",
                "trusted": "",
                "acknowledged": "yes",
            },
        )

        body = response.get_data(as_text=True)

        self.assertEqual(response.status_code, 200)
        self.assertIn("PhishTank", body)
        self.assertIn(
            "temporarily unavailable",
            body,
        )

    def test_health_reports_available_phishtank_feed(self):
        with patch.dict(
            "os.environ",
            {
                "FDF_PHISHTANK_FEED_PATH": str(
                    PHISHTANK_FIXTURE_PATH
                )
            },
            clear=False,
        ):
            app = create_app()

        app.testing = True
        response = app.test_client().get("/health")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.get_json()["phishtank_feed"],
            "available",
        )


if __name__ == "__main__":
    unittest.main()
