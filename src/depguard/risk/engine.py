"""Deterministic finding and scan risk scoring."""

from __future__ import annotations

from depguard.models import Finding, Severity

SEVERITY_SCORE = {
    Severity.CRITICAL: 9.5,
    Severity.HIGH: 8.0,
    Severity.MEDIUM: 5.5,
    Severity.LOW: 3.0,
    Severity.INFO: 0.5,
}


def score_finding(
    finding: Finding,
    *,
    internet_exposed: bool = False,
    direct_dependency: bool = True,
    fix_available: bool = False,
) -> float:
    """Score a finding on a deterministic 0-100 scale and store the result."""
    base = (
        finding.cvss_score if finding.cvss_score is not None else SEVERITY_SCORE[finding.severity]
    ) * 10
    score = base
    if finding.epss_score is not None:
        score += min(max(finding.epss_score, 0), 1) * 12
    if finding.in_kev:
        score += 15
    if internet_exposed:
        score += 8
    if not direct_dependency:
        score -= 5
    if fix_available:
        score += 2
    score *= {"high": 1.0, "medium": 0.85, "low": 0.65}.get(finding.confidence, 0.85)
    finding.risk_score = round(min(100.0, max(0.0, score)), 2)
    return finding.risk_score


def classify_score(score: float) -> Severity:
    """Map a 0-100 score to the project's risk bands."""
    if score >= 85:
        return Severity.CRITICAL
    if score >= 65:
        return Severity.HIGH
    if score >= 40:
        return Severity.MEDIUM
    if score >= 15:
        return Severity.LOW
    return Severity.INFO


def aggregate_scan_score(findings: list[Finding]) -> float:
    """Aggregate findings without allowing a critical result to be diluted."""
    scores = sorted((finding.risk_score for finding in findings), reverse=True)
    if not scores:
        return 0.0
    result = scores[0] + sum(score * 0.12 for score in scores[1:])
    return round(min(100.0, result), 2)
