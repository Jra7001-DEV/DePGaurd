"""CLI behavior tests for scan gating and report artifacts."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
import typer
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from typer.testing import CliRunner

import depguard.cli.main as cli_main
from depguard.cli.main import _check_fail_threshold, _display_results, _finding_dict, app
from depguard.db.models import Base, Role, Scan, ScanResult, Target, User
from depguard.models import Component, Finding, Severity

runner = CliRunner()


def test_help_version_and_authorization_gate() -> None:
    help_result = runner.invoke(app, ["--help"])
    assert help_result.exit_code == 0
    assert "scan" in help_result.stdout
    assert runner.invoke(app, ["version"]).stdout.strip() == "DePGuard 0.1.0"
    denied = runner.invoke(app, ["scan", "url", "https://example.test"])
    assert denied.exit_code != 0
    assert "--auth-confirm" in denied.output


def test_manifest_cli_emits_json_sbom_and_pdf(tmp_path, monkeypatch) -> None:
    manifest = tmp_path / "requirements.txt"
    manifest.write_text("sample-library==1.0.0\n")
    monkeypatch.chdir(tmp_path)
    result = runner.invoke(
        app,
        [
            "scan",
            "manifest",
            str(manifest),
            "--offline",
            "--output",
            "json",
            "--sbom",
            "cyclonedx",
            "--report",
            "pdf",
        ],
    )
    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout.split("SBOM written")[0]) == []
    assert (tmp_path / "depguard-sbom.json").is_file()
    assert (tmp_path / "depguard-report.pdf").is_file()
    assert "SBOM written" in result.output
    assert "Report written" in result.output


def test_fail_threshold_and_output_validation() -> None:
    high_finding = Finding("High", Severity.HIGH, "CVE", "", "")
    with pytest.raises(typer.Exit) as error:
        _check_fail_threshold([high_finding], "high")
    assert error.value.exit_code == 1
    _check_fail_threshold([high_finding], "critical")
    with pytest.raises(typer.BadParameter):
        _display_results([], "xml", False)
    with pytest.raises(typer.BadParameter):
        _check_fail_threshold([], "urgent")
    assert _finding_dict(high_finding)["severity"] == "High"


def test_scan_command_error_branches(tmp_path, monkeypatch) -> None:
    manifest = tmp_path / "requirements.txt"
    manifest.write_text("demo==1.0.0\n")

    class EmptyScanner:
        async def scan(self, paths, *, offline=False):
            del paths, offline
            return [], [], True

    monkeypatch.setattr(cli_main, "ScaScanner", EmptyScanner)
    bad_sbom = runner.invoke(
        app, ["scan", "manifest", str(manifest), "--offline", "--sbom", "spdx"]
    )
    assert bad_sbom.exit_code != 0
    bad_report = runner.invoke(
        app, ["scan", "manifest", str(manifest), "--offline", "--report", "html"]
    )
    assert bad_report.exit_code != 0
    bad_output = runner.invoke(
        app, ["scan", "manifest", str(manifest), "--offline", "--output", "xml"]
    )
    assert bad_output.exit_code != 0

    async def fake_url(*args, **kwargs):
        del args, kwargs
        return []

    monkeypatch.setattr(cli_main, "scan_url", fake_url)
    bad_profile = runner.invoke(
        app, ["scan", "url", "https://example.test", "--auth-confirm", "--profile", "unsafe"]
    )
    assert bad_profile.exit_code != 0
    bad_header = runner.invoke(
        app, ["scan", "url", "https://example.test", "--auth-confirm", "--header", "broken"]
    )
    assert bad_header.exit_code != 0
    valid_url = runner.invoke(
        app,
        [
            "scan",
            "url",
            "https://example.test",
            "--auth-confirm",
            "--header",
            "X-Test: yes",
            "--output",
            "json",
        ],
    )
    assert valid_url.exit_code == 0, valid_url.output

    async def rejected_url(*args, **kwargs):
        del args, kwargs
        raise ValueError("unsafe target")

    monkeypatch.setattr(cli_main, "scan_url", rejected_url)
    rejected = runner.invoke(app, ["scan", "url", "https://example.test", "--auth-confirm"])
    assert rejected.exit_code != 0


def test_full_scan_and_cache_commands(tmp_path, monkeypatch) -> None:
    manifest = tmp_path / "requirements.txt"
    manifest.write_text("demo==1.0.0\n")

    class Scanner:
        async def scan(self, paths, *, offline=False):
            del paths, offline
            return [Component("demo", "1.0.0", "PyPI", "pkg:pypi/demo@1.0.0")], [], False

    monkeypatch.setattr(cli_main, "ScaScanner", Scanner)

    async def fake_url(*args, **kwargs):
        del args, kwargs
        return [Finding("Header", Severity.LOW, "HEADER", "missing", "set")]

    monkeypatch.setattr(cli_main, "scan_url", fake_url)
    denied = runner.invoke(
        app, ["scan", "full", "--url", "https://example.test", "--manifest", str(manifest)]
    )
    assert denied.exit_code != 0
    result = runner.invoke(
        app,
        [
            "scan",
            "full",
            "--url",
            "https://example.test",
            "--manifest",
            str(manifest),
            "--auth-confirm",
            "--offline",
        ],
    )
    assert result.exit_code == 0, result.output

    class FakeCache:
        def stats(self):
            return {"entries": 2, "expired": 1}

        def clear(self):
            return 2

    monkeypatch.setattr(cli_main, "SQLiteCache", FakeCache)
    assert runner.invoke(app, ["cache", "stats"]).exit_code == 0
    assert runner.invoke(app, ["cache", "clear"]).exit_code == 0


def test_history_and_report_formats(tmp_path, monkeypatch) -> None:
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    monkeypatch.setattr("depguard.db.session.SessionLocal", factory)
    with factory.begin() as session:
        role = Role(role_name="User")
        session.add(role)
        session.flush()
        user = User(
            username="owner",
            email="owner@example.test",
            password_hash="hash",
            role_id=role.role_id,
        )
        session.add(user)
        session.flush()
        target = Target(
            target_type="URL",
            target_path_or_url="https://example.test",
            owner_user_id=user.user_id,
            authorization_confirmed=True,
        )
        session.add(target)
        session.flush()
        scan = Scan(
            user_id=user.user_id,
            target_id=target.target_id,
            scan_type="DAST",
            status="completed",
            scan_date=datetime.now(UTC),
        )
        session.add(scan)
        session.flush()
        session.add(
            ScanResult(
                scan_id=scan.scan_id,
                finding_type="HEADER",
                title="Missing CSP",
                severity="Medium",
                evidence="No CSP",
                remediation="Set policy",
                risk_score=55,
            )
        )
        scan_id = scan.scan_id
    monkeypatch.chdir(tmp_path)
    assert runner.invoke(app, ["history"]).exit_code == 0
    assert runner.invoke(app, ["report", str(scan_id), "--format", "json"]).exit_code == 0
    assert (
        json.loads(Path(f"depguard-scan-{scan_id}.json").read_text())[0]["title"] == "Missing CSP"
    )
    assert runner.invoke(app, ["report", str(scan_id), "--format", "csv"]).exit_code == 0
    assert runner.invoke(app, ["report", str(scan_id), "--format", "pdf"]).exit_code == 0
    assert runner.invoke(app, ["report", "999", "--format", "json"]).exit_code != 0
    assert runner.invoke(app, ["report", str(scan_id), "--format", "xml"]).exit_code != 0
    engine.dispose()
