"""DePGuard command-line entrypoint."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

import typer
from rich.console import Console
from rich.table import Table

from depguard import __version__
from depguard.config import get_settings
from depguard.dast.scanner import scan_url
from depguard.feeds.cache import SQLiteCache
from depguard.models import Finding, Severity
from depguard.reports.pdf_report import write_pdf_report
from depguard.reports.sbom import cyclonedx_document
from depguard.risk.engine import aggregate_scan_score, classify_score
from depguard.sca.parsers import ManifestError
from depguard.sca.scanner import ScaScanner

app = typer.Typer(
    name="depguard",
    help="Defensive web vulnerability and dependency scanner.",
    no_args_is_help=True,
)
scan_app = typer.Typer(help="Run authorized web and dependency scans.")
cache_app = typer.Typer(help="Manage the local vulnerability-data cache.")
db_app = typer.Typer(help="Initialize and seed the local database.")
user_app = typer.Typer(help="Manage local dashboard users.")
console = Console()


@app.callback()
def main() -> None:
    """Run DePGuard commands."""


@app.command()
def version() -> None:
    """Print the installed DePGuard version."""
    typer.echo(f"DePGuard {__version__}")


@scan_app.command("manifest")
def scan_manifest(
    files: list[Path] = typer.Argument(..., exists=True, readable=True),
    offline: bool = typer.Option(False, help="Use cached vulnerability data only."),
    sbom: str | None = typer.Option(None, help="Write a CycloneDX SBOM."),
    report: str | None = typer.Option(None, help="Write a PDF report."),
    output: str = typer.Option("table", help="Output as table or json."),
    fail_on: str | None = typer.Option(None, "--fail-on", help="Exit nonzero at this severity."),
) -> None:
    """Scan package manifests without installing or executing dependencies."""
    try:
        components, findings, stale = asyncio.run(
            ScaScanner().scan([str(path) for path in files], offline=offline)
        )
    except ManifestError as exc:
        raise typer.BadParameter(str(exc)) from exc
    _display_results(findings, output, stale)
    if sbom:
        if sbom.lower() != "cyclonedx":
            raise typer.BadParameter("Only CycloneDX output is currently supported")
        Path("depguard-sbom.json").write_text(
            json.dumps(cyclonedx_document(components, findings), indent=2), encoding="utf-8"
        )
        console.print("SBOM written to depguard-sbom.json")
    if report:
        if report.lower() != "pdf":
            raise typer.BadParameter("Only PDF reports are currently supported")
        write_pdf_report(
            Path("depguard-report.pdf"), ", ".join(str(path) for path in files), findings
        )
        console.print("Report written to depguard-report.pdf")
    _check_fail_threshold(findings, fail_on)


@scan_app.command("url")
def scan_web_url(
    target: str,
    auth_confirm: bool = typer.Option(
        False, "--auth-confirm", help="Confirm authorization to scan this target."
    ),
    profile: str = typer.Option("quick", help="Scan profile: quick, standard, or deep."),
    output: str = typer.Option("table", help="Output as table or json."),
    header: list[str] = typer.Option([], "--header", help="Request header in Key:Value form."),
) -> None:
    """Run passive checks against an explicitly authorized URL."""
    if not auth_confirm:
        raise typer.BadParameter("URL scans require --auth-confirm")
    if profile not in {"quick", "standard", "deep"}:
        raise typer.BadParameter("Profile must be quick, standard, or deep")
    request_headers: dict[str, str] = {}
    for item in header:
        key, separator, value = item.partition(":")
        if not separator or not key.strip():
            raise typer.BadParameter("Headers must use Key:Value format")
        request_headers[key.strip()] = value.strip()
    allow_private = get_settings().allow_private_targets
    try:
        findings = asyncio.run(
            scan_url(target, allow_private=allow_private, headers=request_headers)
        )
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc
    _display_results(findings, output, stale=False)


@scan_app.command("full")
def scan_full(
    url: str = typer.Option(..., help="Authorized URL to assess."),
    manifest: Path = typer.Option(..., exists=True, readable=True, help="Dependency manifest."),
    auth_confirm: bool = typer.Option(
        False, "--auth-confirm", help="Confirm URL scan authorization."
    ),
    offline: bool = typer.Option(False, help="Use cached vulnerability data only."),
) -> None:
    """Run passive URL checks and dependency analysis."""
    if not auth_confirm:
        raise typer.BadParameter("Full scans require --auth-confirm")
    allow_private = get_settings().allow_private_targets
    try:
        web_findings = asyncio.run(scan_url(url, allow_private=allow_private))
        components, sca_findings, stale = asyncio.run(
            ScaScanner().scan([str(manifest)], offline=offline)
        )
    except (ValueError, ManifestError) as exc:
        raise typer.BadParameter(str(exc)) from exc
    all_findings = web_findings + sca_findings
    _display_results(all_findings, "table", stale)
    console.print(f"Analyzed {len(components)} dependency component(s).")


@app.command("history")
def history(limit: int = typer.Option(20, min=1, max=100)) -> None:
    """List recent persisted scans."""
    from sqlalchemy import select

    from depguard.db.models import Scan
    from depguard.db.session import SessionLocal

    with SessionLocal() as session:
        records = session.scalars(select(Scan).order_by(Scan.scan_date.desc()).limit(limit)).all()
        table = Table("ID", "Date", "Type", "Status", "Risk")
        for item in records:
            table.add_row(
                str(item.scan_id),
                item.scan_date.isoformat(),
                item.scan_type,
                item.status,
                item.risk_level,
            )
        console.print(table)


@app.command("report")
def report_scan(
    scan_id: int,
    format: str = typer.Option("json", help="Output format: json, csv, or pdf."),
) -> None:
    """Export a stored scan's findings."""
    import csv
    import io

    from sqlalchemy import select

    from depguard.db.models import Scan, ScanResult
    from depguard.db.session import SessionLocal

    with SessionLocal() as session:
        scan = session.get(Scan, scan_id)
        if scan is None:
            raise typer.BadParameter(f"Scan {scan_id} was not found")
        records = session.scalars(select(ScanResult).where(ScanResult.scan_id == scan_id)).all()
        findings = [
            Finding(
                title=item.title,
                severity=Severity(item.severity),
                finding_type=item.finding_type,
                evidence=item.evidence,
                remediation=item.remediation,
                cve_id=item.cve_id,
                component=item.affected_component,
                installed_version=item.installed_version,
                fixed_version=item.fixed_version,
                risk_score=item.risk_score,
            )
            for item in records
        ]
        target = scan.target.target_path_or_url
    output_path = Path(f"depguard-scan-{scan_id}.{format}")
    if format == "json":
        output_path.write_text(json.dumps([_finding_dict(item) for item in findings], indent=2))
    elif format == "csv":
        buffer = io.StringIO()
        writer = csv.DictWriter(
            buffer,
            fieldnames=[
                "title",
                "severity",
                "finding_type",
                "risk_score",
                "evidence",
                "remediation",
            ],
        )
        writer.writeheader()
        for item in findings:
            writer.writerow(
                {
                    "title": item.title,
                    "severity": item.severity.value,
                    "finding_type": item.finding_type,
                    "risk_score": item.risk_score,
                    "evidence": item.evidence,
                    "remediation": item.remediation,
                }
            )
        output_path.write_text(buffer.getvalue(), encoding="utf-8")
    elif format == "pdf":
        write_pdf_report(output_path, target, findings)
    else:
        raise typer.BadParameter("Format must be json, csv, or pdf")
    console.print(f"Report written to {output_path}")


@cache_app.command("stats")
def cache_stats() -> None:
    """Show vulnerability cache size and expired entries."""
    console.print(SQLiteCache().stats())


@cache_app.command("clear")
def cache_clear() -> None:
    """Remove all cached vulnerability responses."""
    console.print(f"Removed {SQLiteCache().clear()} cache entries.")


@cache_app.command("update")
def cache_update(
    files: list[Path] = typer.Argument(..., exists=True, readable=True),
) -> None:
    """Refresh cached data by scanning the supplied manifests."""
    components, findings, _ = asyncio.run(ScaScanner().scan([str(path) for path in files]))
    console.print(f"Refreshed data for {len(components)} component(s); {len(findings)} finding(s).")


@db_app.command("init")
def database_init() -> None:
    """Create missing local database tables."""
    from depguard.db.session import init_db

    init_db()
    console.print("Database schema is ready.")


@db_app.command("seed")
def database_seed() -> None:
    """Create standard role records."""
    from depguard.db.seed import seed_roles

    seed_roles()
    console.print("Standard roles are ready.")


@user_app.command("create")
def user_create(
    username: str,
    email: str = typer.Argument(...),
    role_name: str = typer.Option("Admin", "--role", help="User, Analyst, or Admin."),
) -> None:
    """Create a local dashboard user with an interactive password prompt."""
    from sqlalchemy import select

    from depguard.db.models import Role, User
    from depguard.db.seed import seed_roles
    from depguard.db.session import SessionLocal
    from depguard.security.auth import hash_password

    if role_name not in {"User", "Analyst", "Admin"}:
        raise typer.BadParameter("Role must be User, Analyst, or Admin")
    seed_roles()
    password = typer.prompt("Password (12+ characters)", hide_input=True, confirmation_prompt=True)
    try:
        password_hash = hash_password(password)
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc
    with SessionLocal.begin() as session:
        if session.scalar(select(User).where((User.username == username) | (User.email == email))):
            raise typer.BadParameter("Username or email is already in use")
        role = session.scalar(select(Role).where(Role.role_name == role_name))
        if role is None:
            raise typer.BadParameter("Role configuration is unavailable")
        session.add(
            User(username=username, email=email, password_hash=password_hash, role_id=role.role_id)
        )
    console.print(f"Created {role_name} user {username}.")


@app.command()
def serve(
    host: str = typer.Option("127.0.0.1", help="Bind address."),
    port: int = typer.Option(8000, min=1, max=65535, help="TCP port."),
) -> None:
    """Run the DePGuard dashboard and API."""
    import uvicorn

    uvicorn.run("depguard.api.app:app", host=host, port=port, proxy_headers=False)


def _display_results(findings: list[Finding], output: str, stale: bool) -> None:
    """Render findings as JSON or a concise Rich table."""
    if output == "json":
        typer.echo(json.dumps([_finding_dict(item) for item in findings], indent=2))
        return
    if output != "table":
        raise typer.BadParameter("Output must be table or json")
    table = Table("Severity", "Risk", "Finding", "Component", "Fixed version")
    for finding in findings:
        table.add_row(
            finding.severity.value,
            f"{finding.risk_score:.1f}",
            finding.title,
            finding.component or "Web target",
            finding.fixed_version or "-",
        )
    console.print(table)
    score = aggregate_scan_score(findings)
    console.print(f"Scan risk: {score:.1f}/100 ({classify_score(score).value})")
    if stale:
        console.print("Vulnerability data came from a stale cache.", style="yellow")


def _finding_dict(finding: Finding) -> dict[str, Any]:
    return {
        "title": finding.title,
        "severity": finding.severity.value,
        "finding_type": finding.finding_type,
        "evidence": finding.evidence,
        "remediation": finding.remediation,
        "cve_id": finding.cve_id,
        "component": finding.component,
        "installed_version": finding.installed_version,
        "fixed_version": finding.fixed_version,
        "risk_score": finding.risk_score,
    }


def _check_fail_threshold(findings: list[Finding], fail_on: str | None) -> None:
    if fail_on is None:
        return
    order = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
    normalized = next((item for item in order if item.value.lower() == fail_on.lower()), None)
    if normalized is None:
        raise typer.BadParameter("--fail-on must be critical, high, medium, low, or info")
    threshold = order.index(normalized)
    if any(order.index(finding.severity) >= threshold for finding in findings):
        raise typer.Exit(code=1)


app.add_typer(scan_app, name="scan")
app.add_typer(cache_app, name="cache")
app.add_typer(db_app, name="db")
app.add_typer(user_app, name="user")


if __name__ == "__main__":
    app()
