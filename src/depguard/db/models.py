"""SQLAlchemy persistence schema for users, scans, findings, and cache data."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    String,
    Text,
    func,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    """Base class for all ORM models."""


class Role(Base):
    __tablename__ = "roles"

    role_id: Mapped[int] = mapped_column(primary_key=True)
    role_name: Mapped[str] = mapped_column(String(32), unique=True, nullable=False)
    users: Mapped[list[User]] = relationship(back_populates="role")


class User(Base):
    __tablename__ = "users"

    user_id: Mapped[int] = mapped_column(primary_key=True)
    role_id: Mapped[int] = mapped_column(ForeignKey("roles.role_id"), index=True)
    username: Mapped[str] = mapped_column(String(80), unique=True, nullable=False)
    email: Mapped[str] = mapped_column(String(254), unique=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    last_login: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    role: Mapped[Role] = relationship(back_populates="users")


class Target(Base):
    __tablename__ = "targets"

    target_id: Mapped[int] = mapped_column(primary_key=True)
    target_type: Mapped[str] = mapped_column(String(16), nullable=False)
    target_path_or_url: Mapped[str] = mapped_column(Text, nullable=False)
    owner_user_id: Mapped[int] = mapped_column(ForeignKey("users.user_id"), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    authorization_confirmed: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    scans: Mapped[list[Scan]] = relationship(back_populates="target")


class Scan(Base):
    __tablename__ = "scans"
    __table_args__ = (Index("ix_scans_scan_date", "scan_date"),)

    scan_id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.user_id"), index=True)
    target_id: Mapped[int] = mapped_column(ForeignKey("targets.target_id"), index=True)
    scan_date: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    status: Mapped[str] = mapped_column(String(16), default="queued", nullable=False)
    scan_type: Mapped[str] = mapped_column(String(16), default="DAST", nullable=False)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    risk_score: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    risk_level: Mapped[str] = mapped_column(String(16), default="Info", nullable=False)
    target: Mapped[Target] = relationship(back_populates="scans")
    results: Mapped[list[ScanResult]] = relationship(
        back_populates="scan", cascade="all, delete-orphan"
    )
    report: Mapped[Report | None] = relationship(back_populates="scan", uselist=False)


class Vulnerability(Base):
    __tablename__ = "vulnerabilities"
    __table_args__ = (Index("ix_vulnerabilities_severity", "severity"),)

    cve_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    cvss_score: Mapped[float | None] = mapped_column(Float)
    description: Mapped[str] = mapped_column(Text, default="", nullable=False)
    cvss_vector: Mapped[str | None] = mapped_column(String(255))
    cwe_ids: Mapped[list[str]] = mapped_column(JSON, default=list)
    epss_score: Mapped[float | None] = mapped_column(Float)
    in_kev: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    published: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_modified: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    reference_urls: Mapped[list[str]] = mapped_column(JSON, default=list)
    source: Mapped[str] = mapped_column(String(32), default="OSV", nullable=False)
    fetched_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class ScanResult(Base):
    __tablename__ = "scan_results"
    __table_args__ = (Index("ix_scan_results_cve_id", "cve_id"),)

    result_id: Mapped[int] = mapped_column(primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.scan_id"), index=True)
    cve_id: Mapped[str | None] = mapped_column(ForeignKey("vulnerabilities.cve_id"), nullable=True)
    affected_component: Mapped[str | None] = mapped_column(String(255))
    finding_type: Mapped[str] = mapped_column(String(24), nullable=False)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    evidence: Mapped[str] = mapped_column(Text, default="", nullable=False)
    remediation: Mapped[str] = mapped_column(Text, default="", nullable=False)
    installed_version: Mapped[str | None] = mapped_column(String(255))
    fixed_version: Mapped[str | None] = mapped_column(String(255))
    risk_score: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    false_positive: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    status: Mapped[str] = mapped_column(String(16), default="open", nullable=False)
    scan: Mapped[Scan] = relationship(back_populates="results")


class Report(Base):
    __tablename__ = "reports"

    report_id: Mapped[int] = mapped_column(primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.scan_id"), unique=True, index=True)
    report_path: Mapped[str] = mapped_column(Text, nullable=False)
    generated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    format: Mapped[str] = mapped_column(String(16), nullable=False)
    scan: Mapped[Scan] = relationship(back_populates="report")


class ComponentRecord(Base):
    __tablename__ = "components"

    component_id: Mapped[int] = mapped_column(primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.scan_id"), index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    version: Mapped[str] = mapped_column(String(255), nullable=False)
    ecosystem: Mapped[str] = mapped_column(String(32), nullable=False)
    purl: Mapped[str] = mapped_column(Text, nullable=False)
    license: Mapped[str | None] = mapped_column(String(255))
    direct: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)


class CacheEntry(Base):
    __tablename__ = "cache_entries"

    cache_key: Mapped[str] = mapped_column(String(255), primary_key=True)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class AuditLog(Base):
    __tablename__ = "audit_logs"
    __table_args__ = (Index("ix_audit_logs_user_id", "user_id"),)

    audit_id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int | None] = mapped_column(ForeignKey("users.user_id"), nullable=True)
    action: Mapped[str] = mapped_column(String(100), nullable=False)
    ip_address: Mapped[str | None] = mapped_column(String(64))
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    details: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
