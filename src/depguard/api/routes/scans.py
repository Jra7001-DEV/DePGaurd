"""Authenticated DAST scan submission and result endpoints."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime

from fastapi import APIRouter, BackgroundTasks, Depends, Header, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from depguard.config import get_settings
from depguard.dast.scanner import scan_url
from depguard.db.models import AuditLog, Scan, ScanResult, Target, User
from depguard.db.session import SessionLocal, get_session
from depguard.models import Finding
from depguard.risk.engine import aggregate_scan_score, classify_score
from depguard.security.ssrf_guard import GuardedResolver, TargetRejected, parse_target_url

router = APIRouter()


class UrlScanRequest(BaseModel):
    target_url: str = Field(min_length=8, max_length=2048)
    authorization_confirmed: bool
    profile: str = "quick"


class FalsePositiveUpdate(BaseModel):
    false_positive: bool


def _authenticated_user(request: Request, session: Session) -> User:
    user_id = request.session.get("user_id")
    user = session.get(User, user_id) if user_id else None
    if user is None or not user.is_active:
        raise HTTPException(status_code=401, detail="Authentication required")
    return user


def _require_csrf(request: Request, csrf_header: str | None) -> None:
    expected = request.session.get("csrf")
    if (
        not expected
        or not csrf_header
        or not __import__("hmac").compare_digest(expected, csrf_header)
    ):
        raise HTTPException(status_code=403, detail="CSRF token missing or invalid")


@router.post("", status_code=202)
def create_scan(
    details: UrlScanRequest,
    background_tasks: BackgroundTasks,
    request: Request,
    session: Session = Depends(get_session),
    csrf_token: str | None = Header(default=None, alias="X-CSRF-Token"),
) -> dict[str, int | str]:
    """Queue one authorized URL scan after SSRF validation."""
    user = _authenticated_user(request, session)
    _require_csrf(request, csrf_token)
    if not details.authorization_confirmed:
        raise HTTPException(status_code=400, detail="Explicit scan authorization is required")
    if details.profile not in {"quick", "standard", "deep"}:
        raise HTTPException(status_code=422, detail="Profile must be quick, standard, or deep")
    try:
        parsed = parse_target_url(details.target_url)
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        allow_private = get_settings().allow_private_targets
        asyncio.run(
            GuardedResolver(allow_private=allow_private).resolve(parsed.hostname or "", port)
        )
    except TargetRejected as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    target = Target(
        target_type="URL",
        target_path_or_url=details.target_url,
        owner_user_id=user.user_id,
        authorization_confirmed=True,
    )
    session.add(target)
    session.flush()
    scan = Scan(user_id=user.user_id, target_id=target.target_id, scan_type="DAST", status="queued")
    session.add(scan)
    session.add(
        AuditLog(
            user_id=user.user_id,
            action="scan.authorization_confirmed",
            ip_address=request.client.host if request.client else None,
            details={"target": details.target_url, "profile": details.profile},
        )
    )
    session.commit()
    background_tasks.add_task(_run_scan, scan.scan_id, details.target_url, allow_private)
    return {"scan_id": scan.scan_id, "status": scan.status}


@router.get("")
def list_scans(
    request: Request,
    session: Session = Depends(get_session),
    limit: int = 50,
    offset: int = 0,
) -> list[dict[str, object]]:
    """List the current user's scans with bounded pagination."""
    user = _authenticated_user(request, session)
    if not 1 <= limit <= 100 or offset < 0:
        raise HTTPException(status_code=422, detail="Invalid pagination bounds")
    scans = session.scalars(
        select(Scan)
        .where(Scan.user_id == user.user_id)
        .order_by(Scan.scan_date.desc())
        .limit(limit)
        .offset(offset)
    ).all()
    return [
        {
            "scan_id": scan.scan_id,
            "status": scan.status,
            "scan_type": scan.scan_type,
            "scan_date": scan.scan_date.isoformat(),
            "risk_score": scan.risk_score,
            "risk_level": scan.risk_level,
        }
        for scan in scans
    ]


@router.get("/{scan_id}")
def get_scan(
    scan_id: int,
    request: Request,
    session: Session = Depends(get_session),
) -> dict[str, object]:
    """Return a scan and its findings when owned by the current user."""
    user = _authenticated_user(request, session)
    scan = session.scalar(select(Scan).where(Scan.scan_id == scan_id, Scan.user_id == user.user_id))
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    return {
        "scan_id": scan.scan_id,
        "status": scan.status,
        "risk_score": scan.risk_score,
        "risk_level": scan.risk_level,
        "findings": [
            {
                "result_id": result.result_id,
                "title": result.title,
                "finding_type": result.finding_type,
                "severity": result.severity,
                "risk_score": result.risk_score,
                "evidence": result.evidence,
                "remediation": result.remediation,
                "false_positive": result.false_positive,
                "status": result.status,
            }
            for result in scan.results
        ],
    }


@router.patch("/{scan_id}/findings/{result_id}/false-positive")
def mark_false_positive(
    scan_id: int,
    result_id: int,
    details: FalsePositiveUpdate,
    request: Request,
    session: Session = Depends(get_session),
    csrf_token: str | None = Header(default=None, alias="X-CSRF-Token"),
) -> dict[str, bool]:
    """Mark an owned finding as false positive or restore its open status."""
    user = _authenticated_user(request, session)
    _require_csrf(request, csrf_token)
    result = session.scalar(
        select(ScanResult)
        .join(Scan)
        .where(
            Scan.scan_id == scan_id, Scan.user_id == user.user_id, ScanResult.result_id == result_id
        )
    )
    if result is None:
        raise HTTPException(status_code=404, detail="Finding not found")
    result.false_positive = details.false_positive
    result.status = "accepted" if details.false_positive else "open"
    scan = session.get(Scan, scan_id)
    if scan:
        active = [item for item in scan.results if not item.false_positive]
        scan.risk_score = aggregate_scan_score(
            [
                Finding(
                    title=item.title,
                    severity=__import__("depguard.models", fromlist=["Severity"]).Severity(
                        item.severity
                    ),
                    finding_type=item.finding_type,
                    evidence=item.evidence,
                    remediation=item.remediation,
                    risk_score=item.risk_score,
                )
                for item in active
            ]
        )
        scan.risk_level = classify_score(scan.risk_score).value
    session.commit()
    return {"false_positive": result.false_positive}


@router.post("/{scan_id}/cancel")
def cancel_scan(
    scan_id: int,
    request: Request,
    session: Session = Depends(get_session),
    csrf_token: str | None = Header(default=None, alias="X-CSRF-Token"),
) -> dict[str, str]:
    """Mark an owned queued or running scan cancelled."""
    user = _authenticated_user(request, session)
    _require_csrf(request, csrf_token)
    scan = session.scalar(select(Scan).where(Scan.scan_id == scan_id, Scan.user_id == user.user_id))
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan.status not in {"queued", "running"}:
        raise HTTPException(status_code=409, detail="Scan is no longer active")
    scan.status = "cancelled"
    scan.finished_at = datetime.now(UTC)
    session.commit()
    return {"status": "cancelled"}


def _run_scan(scan_id: int, target_url: str, allow_private: bool) -> None:
    """Execute a queued scan and persist findings without blocking the API request."""
    with SessionLocal.begin() as session:
        scan = session.get(Scan, scan_id)
        if scan is None or scan.status == "cancelled":
            return
        scan.status = "running"
        scan.started_at = datetime.now(UTC)
    try:
        findings = asyncio.run(scan_url(target_url, allow_private=allow_private))
        with SessionLocal.begin() as session:
            scan = session.get(Scan, scan_id)
            if scan is None or scan.status == "cancelled":
                return
            for finding in findings:
                session.add(_to_record(scan_id, finding))
            scan.risk_score = aggregate_scan_score(findings)
            scan.risk_level = classify_score(scan.risk_score).value
            scan.status = "completed"
            scan.finished_at = datetime.now(UTC)
    except Exception:
        with SessionLocal.begin() as session:
            scan = session.get(Scan, scan_id)
            if scan and scan.status != "cancelled":
                scan.status = "failed"
                scan.finished_at = datetime.now(UTC)


def _to_record(scan_id: int, finding: Finding) -> ScanResult:
    return ScanResult(
        scan_id=scan_id,
        finding_type=finding.finding_type,
        title=finding.title,
        severity=finding.severity.value,
        evidence=finding.evidence,
        remediation=finding.remediation,
        affected_component=finding.component,
        installed_version=finding.installed_version,
        fixed_version=finding.fixed_version,
        risk_score=finding.risk_score,
    )
