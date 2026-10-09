from __future__ import annotations

import os
from dataclasses import asdict

from flask import Flask, render_template, request
from local_threat_lookup import lookup_local_feed
from whoisxml_lookup import WhoisXMLClient
from result_summary import summarize_result
from domain_structure import domain_parts
from phishtank_feed import (
    build_phishtank_index,
    load_phishtank_json,
    lookup_phishtank_index,
)
from threat_intelligence import ThreatIntelligenceFinding
from idnHomoglyphDetector import (
    CONFUSABLES_VERSION,
    analyze,
    defang_hostname,
    normalize_trusted_domain,
    sanitized_defanged_display,
)


MAX_INPUT_LENGTH = 2048
MAX_TRUSTED_LENGTH = 253


def create_app() -> Flask:
    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = 16 * 1024
    app.config["FABRICATED_THREAT_LOOKUP_ENABLED"] = (
      os.environ.get(
        "FDF_ENABLE_FABRICATED_THREAT_FEED",
        "",
    ).casefold()
    in {"1", "true", "yes"}
    )
    app.config["WHOISXML_ENABLED"] = os.environ.get(
        "FDF_ENABLE_WHOISXML", ""
    ).casefold() in {"1", "true", "yes"}
    whoisxml_client = WhoisXMLClient(os.environ.get("WHOISXML_API_KEY", ""))

    @app.context_processor
    def intelligence_configuration():
        return {"whoisxml_enabled": app.config["WHOISXML_ENABLED"]}

    phishtank_feed_path = os.environ.get(
      "FDF_PHISHTANK_FEED_PATH",
        "",
    ).strip()

    phishtank_index = None
    phishtank_feed_status = "disabled"

    if phishtank_feed_path:
        try:
            phishtank_records = load_phishtank_json(
                phishtank_feed_path
            )
            phishtank_index = build_phishtank_index(
                phishtank_records
            )
            phishtank_feed_status = "available"
        except ValueError:
            phishtank_feed_status = "unavailable"
            app.logger.warning(
                "Configured PhishTank feed could not be loaded"
            )

    app.config["PHISHTANK_FEED_CONFIGURED"] = bool(
        phishtank_feed_path
    )
    app.config["PHISHTANK_FEED_STATUS"] = (
        phishtank_feed_status
    )

    @app.after_request
    def security_headers(response):
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "style-src 'self'; "
            "img-src 'self' data:; "
            "form-action 'self'; "
            "base-uri 'none'; "
            "object-src 'none'; "
            "frame-ancestors https://sites.google.com "
            "https://*.googleusercontent.com "
            "https://frederickdataforensics.net "
            "https://www.frederickdataforensics.net"
        )
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Permissions-Policy"] = (
            "camera=(), microphone=(), geolocation=(), payment=(), usb=()"
        )
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.get("/")
    def index():
        return render_template(
            "index.html",
            report=None,
            intelligence_findings=None,
            fabricated_feed_enabled=app.config[
            "FABRICATED_THREAT_LOOKUP_ENABLED"
            ],
            error=None,
            submitted_value="",
            trusted_value="",
            confusables_version=CONFUSABLES_VERSION,
        )

    @app.post("/analyze")
    def analyze_submission():
        value = request.form.get("value", "").strip()
        trusted = request.form.get("trusted", "").strip()
        acknowledged = request.form.get("acknowledged") == "yes"
        error = None
        report_data = None
        intelligence_data = None
        display_value = ""
        display_trusted = ""

        if not acknowledged:
            error = "Please acknowledge the tool's limitations before analyzing."
        elif not value:
            error = "Enter a domain or link to analyze."
        elif len(value) > MAX_INPUT_LENGTH:
            error = "The submitted value is too long. Enter a domain or ordinary link."
        elif len(trusted) > MAX_TRUSTED_LENGTH:
            error = "The trusted comparison domain is too long."
        else:
            try:
                trusted_domains = [trusted] if trusted else []
                report = analyze(value, trusted_domains)
                report_data = asdict(report)

                display_trusted = (
                    normalize_trusted_domain(trusted) if trusted else ""
                )

                # Do not reflect a full URL that may contain a private path,
                # query string, fragment, or embedded credentials.
                report_data["input_value"] = report.hostname
                report_data["defanged_input"] = (
                    sanitized_defanged_display(value)
                )
                report_data["defanged_unicode"] = defang_hostname(
                    report.unicode_hostname
                )
                report_data["defanged_ascii"] = defang_hostname(
                    report.ascii_hostname
                )
                report_data["comparison_domain"] = display_trusted
                report_data["defanged_comparison"] = (
                    defang_hostname(display_trusted)
                    if display_trusted
                    else ""
                )
                report_data["display_verdict"] = {
                    "low risk": (
                        "No supported domain-name indicators detected"
                    ),
                    "suspicious": (
                        "Supported domain-name indicators detected"
                    ),
                    "high risk": (
                        "Strong domain-name impersonation indicators detected"
                    ),
                }.get(report.verdict, report.verdict)

                concern = {"high risk": "High", "suspicious": "Moderate"}.get(report.verdict, "Low")
                report_data["concern"] = concern
                boundary = domain_parts(report.ascii_hostname)
                report_data["site_domain"] = (
                    defang_hostname(boundary["domain"]) if boundary["domain"] else None
                )
                report_data["misleading_subdomain"] = any(
                    f.reason == "Misleading trusted name in subdomain" for f in report.findings
                )
                labels = {
                    "Misleading trusted name in subdomain": "The expected website name appears in front of a different site domain",
                    "Trusted-domain impersonation": "Closely resembles the expected website",
                    "ASCII look-alike substitution": "A number or letter was substituted",
                    "Mixed writing systems within a label": "Characters from different writing systems are mixed",
                    "Unicode hostname": "The domain contains international characters; these can also be legitimate",
                    "ASCII-like homoglyphs": "Some characters resemble ordinary letters",
                    "Hyphen manipulation": "Hyphens change the expected website name",
                    "Adjacent-character transposition": "Two neighboring characters are reversed",
                    "ASCII typosquatting similarity": "The spelling is close to the expected website",
                    "Punycode label": "The domain uses an encoded international name",
                }
                report_data["plain_findings"] = list(dict.fromkeys(
                    labels.get(f.reason, f.reason) for f in report.findings
                ))
                report_data["character_explanations"] = []
                if display_trusted and len(report.unicode_hostname) == len(display_trusted):
                    for position, (actual, expected) in enumerate(
                        zip(report.unicode_hostname, display_trusted), start=1
                    ):
                        if actual != expected:
                            report_data["character_explanations"].append({
                                "position": position, "actual": actual, "expected": expected,
                            })

                display_value = report.hostname

                intelligence_findings = []

                if phishtank_index is not None:
                    intelligence_findings.extend(
                        lookup_phishtank_index(
                            phishtank_index,
                            value,
                        )
                    )
                elif app.config[
                    "PHISHTANK_FEED_CONFIGURED"
                ]:
                    intelligence_findings.append(
                        ThreatIntelligenceFinding(
                            source="PhishTank",
                            status="unavailable",
                            classification="phishing",
                            match_type="none",
                            verified=False,
                            detail=(
                                "The PhishTank feed is temporarily "
                                "unavailable. No PhishTank determination "
                                "was made."
                            ),
                        )
                    )

                if app.config[
                    "FABRICATED_THREAT_LOOKUP_ENABLED"
                ]:
                    intelligence_findings.extend(
                        lookup_local_feed(value)
                    )

                if app.config["WHOISXML_ENABLED"]:
                    intelligence_findings.append(
                        whoisxml_client.lookup(report.ascii_hostname)
                    )

                report_data["summary"] = summarize_result(
                    report, intelligence_findings,
                    test_data=app.config["FABRICATED_THREAT_LOOKUP_ENABLED"],
                )
                report_data["threat_listed"] = any(
                    f.status == "listed" for f in intelligence_findings
                )

                if intelligence_findings:
                    intelligence_data = [
                        finding.to_dict()
                        for finding in intelligence_findings
                    ]
            except (UnicodeError, ValueError) as exc:
                error = f"The hostname could not be analyzed: {exc}"

        return render_template(
            "index.html",
            report=report_data,
            intelligence_findings=intelligence_data,
            fabricated_feed_enabled=app.config[
                "FABRICATED_THREAT_LOOKUP_ENABLED"
            ],
            error=error,
            submitted_value=display_value,
            trusted_value=display_trusted,
            confusables_version=CONFUSABLES_VERSION,
        ), 400 if error else 200
    @app.get("/health")
    def health():
        return {
            "status": "ok",
            "confusables_version": CONFUSABLES_VERSION,
            "phishtank_feed": app.config[
                "PHISHTANK_FEED_STATUS"
            ],
        }

    return app


app = create_app()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "8080")))
