"""Tests for risk scoring and generated SBOM structures."""

from pathlib import Path

from depguard.models import Component, Finding, Severity
from depguard.reports.pdf_report import write_pdf_report
from depguard.reports.sbom import cyclonedx_document
from depguard.risk.engine import aggregate_scan_score, classify_score, score_finding


def test_risk_modifiers_and_classification() -> None:
    finding = Finding(
        "Known issue", Severity.HIGH, "CVE", "", "Upgrade", cvss_score=8.0, in_kev=True
    )
    score = score_finding(finding, internet_exposed=True, fix_available=True)
    assert score >= 85
    assert classify_score(score) == Severity.CRITICAL
    assert aggregate_scan_score([finding]) == score
    assert aggregate_scan_score([]) == 0


def test_cyclonedx_includes_components_and_vulnerabilities() -> None:
    component = Component("demo", "1.0.0", "npm", "pkg:npm/demo@1.0.0")
    finding = Finding(
        "Advisory",
        Severity.HIGH,
        "CVE",
        "evidence",
        "Upgrade",
        cve_id="CVE-2025-1234",
        component="demo",
        installed_version="1.0.0",
        cvss_score=8.1,
    )
    document = cyclonedx_document([component], [finding])
    assert document["specVersion"] == "1.5"
    assert document["components"][0]["purl"] == component.purl
    assert document["vulnerabilities"][0]["id"] == "CVE-2025-1234"


def test_pdf_report_is_generated(tmp_path: Path) -> None:
    output = tmp_path / "report.pdf"
    finding = Finding("Missing policy", Severity.MEDIUM, "HEADER", "No CSP", "Add CSP")
    write_pdf_report(output, "https://example.test", [finding])
    assert output.read_bytes().startswith(b"%PDF-")
