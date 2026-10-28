"""SCA orchestration over normalized manifests and OSV results."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from cvss import CVSS3, CVSS4
from packaging.version import InvalidVersion, Version
from semantic_version import Version as NpmVersion

from depguard.feeds.osv import OsvClient
from depguard.models import Component, Finding, Severity
from depguard.risk.engine import score_finding
from depguard.sca.parsers import parse_manifest


class ScaScanner:
    """Analyze one or more dependency manifests without executing them."""

    def __init__(self, osv: OsvClient | None = None) -> None:
        self.osv = osv or OsvClient()

    async def scan(
        self, paths: list[str], *, offline: bool = False
    ) -> tuple[list[Component], list[Finding], bool]:
        """Parse manifests, query vulnerability data, and return findings."""
        components: list[Component] = []
        for manifest_path in paths:
            components.extend(parse_manifest(Path(manifest_path)))
        results, stale = await self.osv.lookup(components, offline=offline)
        findings: list[Finding] = []
        for component, result in zip(components, results, strict=True):
            seen_advisories: set[str] = set()
            for vulnerability in result.get("vulns", []):
                finding = _finding_from_osv(component, vulnerability, stale=stale)
                aliases = [str(item) for item in vulnerability.get("aliases", [])]
                advisory_key = finding.cve_id or next(
                    iter(sorted(aliases)), str(vulnerability.get("id", ""))
                )
                if advisory_key in seen_advisories:
                    continue
                seen_advisories.add(advisory_key)
                score_finding(
                    finding,
                    direct_dependency=component.direct,
                    fix_available=finding.fixed_version is not None,
                )
                findings.append(finding)
        return components, findings, stale


def _finding_from_osv(
    component: Component, vulnerability: dict[str, Any], *, stale: bool
) -> Finding:
    """Convert an OSV record into a normalized SCA finding."""
    aliases = vulnerability.get("aliases", [])
    cve_id = next((alias for alias in aliases if str(alias).startswith("CVE-")), None)
    cve_id = cve_id or vulnerability.get("id")
    score, severity = _osv_severity(vulnerability)
    fixed_version = _fixed_version(vulnerability, component)
    references = [item["url"] for item in vulnerability.get("references", []) if item.get("url")]
    return Finding(
        title=vulnerability.get("summary") or vulnerability.get("id", "Known vulnerability"),
        severity=severity,
        finding_type="CVE",
        evidence=f"{component.name}@{component.version} affected by {cve_id}"
        + (" (cached/stale data)" if stale else ""),
        remediation=(
            f"Upgrade to {fixed_version}"
            if fixed_version
            else "Review upstream advisories and upgrade"
        ),
        cve_id=cve_id,
        component=component.name,
        installed_version=component.version,
        fixed_version=fixed_version,
        cvss_score=score,
        references=references,
    )


def _osv_severity(vulnerability: dict[str, Any]) -> tuple[float | None, Severity]:
    for severity in vulnerability.get("severity", []):
        vector = str(severity.get("score", ""))
        try:
            if vector.startswith("CVSS:4."):
                score = float(CVSS4(vector).scores()[0])
            elif vector.startswith("CVSS:3."):
                score = float(CVSS3(vector).scores()[0])
            else:
                score = float(vector)
        except Exception:
            continue
        if 0 <= score <= 10:
            return score, _severity_for_score(score)
    database_severity = str(vulnerability.get("database_specific", {}).get("severity", ""))
    mapping = {
        "CRITICAL": Severity.CRITICAL,
        "HIGH": Severity.HIGH,
        "MODERATE": Severity.MEDIUM,
        "MEDIUM": Severity.MEDIUM,
        "LOW": Severity.LOW,
    }
    return None, mapping.get(database_severity.upper(), Severity.MEDIUM)


def _severity_for_score(score: float) -> Severity:
    if score >= 9:
        return Severity.CRITICAL
    if score >= 7:
        return Severity.HIGH
    if score >= 4:
        return Severity.MEDIUM
    if score > 0:
        return Severity.LOW
    return Severity.INFO


def _fixed_version(vulnerability: dict[str, Any], component: Component) -> str | None:
    """Return the nearest documented fix newer than the installed version."""
    fixed: list[str] = []
    for affected in vulnerability.get("affected", []):
        package = affected.get("package", {}).get("name", "")
        if package and package.casefold() != component.name.casefold():
            continue
        for version_range in affected.get("ranges", []):
            for event in version_range.get("events", []):
                candidate = event.get("fixed")
                if candidate and _version_is_newer(
                    candidate, component.version, component.ecosystem
                ):
                    fixed.append(candidate)
    if not fixed:
        return None
    return min(fixed, key=lambda version: _version_order(version, component.ecosystem))


def _version_is_newer(candidate: str, installed: str, ecosystem: str) -> bool:
    try:
        return _version_order(candidate, ecosystem) > _version_order(installed, ecosystem)
    except (InvalidVersion, ValueError):
        return False


def _version_order(version: str, ecosystem: str) -> Version | NpmVersion:
    if ecosystem.lower() == "npm":
        return NpmVersion.coerce(version.lstrip("v"))
    return Version(version)
