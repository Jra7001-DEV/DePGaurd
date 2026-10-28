"""Shared domain models for scan results."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum


class Severity(StrEnum):
    """Normalized finding severity levels."""

    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"


@dataclass(slots=True)
class Component:
    """A normalized software dependency."""

    name: str
    version: str
    ecosystem: str
    purl: str
    direct: bool = True
    license: str | None = None
    source: str | None = None


@dataclass(slots=True)
class Finding:
    """A DAST or SCA result with remediation context."""

    title: str
    severity: Severity
    finding_type: str
    evidence: str
    remediation: str
    cve_id: str | None = None
    component: str | None = None
    installed_version: str | None = None
    fixed_version: str | None = None
    cvss_score: float | None = None
    epss_score: float | None = None
    in_kev: bool = False
    references: list[str] = field(default_factory=list)
    risk_score: float = 0.0
    confidence: str = "high"
