"""Focused tests for manifest parsing, matching, and offline behavior."""

from __future__ import annotations

import asyncio
import json
import sqlite3

import httpx
import pytest

from depguard.feeds.cache import SQLiteCache
from depguard.feeds.osv import OsvClient
from depguard.models import Component
from depguard.sca.matcher import version_matches
from depguard.sca.parsers import ManifestError, parse_manifest
from depguard.sca.scanner import ScaScanner, _finding_from_osv


def test_parse_package_json_and_lockfile_v3(tmp_path) -> None:
    package_json = tmp_path / "package.json"
    package_json.write_text(json.dumps({"dependencies": {"express": "^4.18.0"}}))
    assert parse_manifest(package_json)[0].version == "^4.18.0"

    lockfile = tmp_path / "package-lock.json"
    lockfile.write_text(
        json.dumps(
            {
                "lockfileVersion": 3,
                "packages": {
                    "": {"name": "demo"},
                    "node_modules/express": {"version": "4.18.2"},
                    "node_modules/express/node_modules/accepts": {"version": "1.3.8"},
                },
            }
        )
    )
    components = parse_manifest(lockfile)
    assert {item.name for item in components} == {"express", "accepts"}
    assert next(item for item in components if item.name == "accepts").direct is False


def test_requirements_recursive_include_is_confined(tmp_path) -> None:
    included = tmp_path / "base.txt"
    included.write_text("urllib3>=1.26,<2\n")
    requirements = tmp_path / "requirements.txt"
    requirements.write_text("-r base.txt\nrequests[security]==2.31.0; python_version >= '3.10'\n")
    assert {item.name for item in parse_manifest(requirements)} == {"urllib3", "requests"}
    requirements.write_text("-r ../outside.txt\n")
    with pytest.raises(ManifestError):
        parse_manifest(requirements)


def test_malformed_and_oversized_manifest_rejected(tmp_path) -> None:
    manifest = tmp_path / "package.json"
    manifest.write_text("{")
    with pytest.raises(ManifestError):
        parse_manifest(manifest)
    manifest.write_text("x" * (2_000_001))
    with pytest.raises(ManifestError):
        parse_manifest(manifest)


def test_npm_v1_and_cyclic_requirements_include(tmp_path) -> None:
    lockfile = tmp_path / "package-lock.json"
    lockfile.write_text(
        json.dumps(
            {
                "lockfileVersion": 1,
                "dependencies": {
                    "alpha": {
                        "version": "1.0.0",
                        "dependencies": {"beta": {"version": "2.0.0"}},
                    }
                },
            }
        )
    )
    components = parse_manifest(lockfile)
    assert len(components) == 2
    assert next(item for item in components if item.name == "beta").direct is False

    main = tmp_path / "requirements.txt"
    included = tmp_path / "nested.txt"
    main.write_text("-r nested.txt\nrequests==2.31.0  # pinned\n")
    included.write_text("-r requirements.txt\n-e git+https://example.test/repo#egg=demo-vcs\n")
    parsed = parse_manifest(main)
    assert {item.name for item in parsed} == {"requests", "demo-vcs"}


def test_malformed_pyproject_and_unsupported_manifest(tmp_path) -> None:
    project = tmp_path / "pyproject.toml"
    project.write_text("[project\ndependencies = [")
    with pytest.raises(ManifestError):
        parse_manifest(project)
    with pytest.raises(ManifestError):
        parse_manifest(tmp_path / "unknown.lock")


@pytest.mark.parametrize(
    ("version", "version_range", "ecosystem", "expected"),
    [
        ("4.17.15", ">=4.0,<5", "PyPI", True),
        ("5.0.0", ">=4.0,<5", "PyPI", False),
        ("1.2.3", "^1.2.0", "npm", True),
        ("2.0.0", "^1.2.0", "npm", False),
    ],
)
def test_version_matching(version: str, version_range: str, ecosystem: str, expected: bool) -> None:
    assert version_matches(version, version_range, ecosystem) is expected


def test_offline_scan_without_cache_is_graceful(tmp_path) -> None:
    path = tmp_path / "requirements.txt"
    path.write_text("demo-package==1.0.0\n")
    cache = SQLiteCache(tmp_path / "cache.sqlite3")
    components, findings, stale = asyncio.run(
        ScaScanner(OsvClient(cache=cache)).scan([str(path)], offline=True)
    )
    assert components[0].name == "demo-package"
    assert findings == []
    assert stale is False


def test_component_model_is_stable() -> None:
    component = Component("Django", "4.2.0", "PyPI", "pkg:pypi/django@4.2.0")
    assert component.direct is True


def test_pipfile_and_pyproject_parsing(tmp_path) -> None:
    pipfile = tmp_path / "Pipfile.lock"
    pipfile.write_text(
        json.dumps(
            {
                "default": {"requests": {"version": "==2.31.0"}},
                "develop": {"pytest": {"version": "==8.0.0"}},
            }
        )
    )
    assert {item.name for item in parse_manifest(pipfile)} == {"requests", "pytest"}

    project = tmp_path / "pyproject.toml"
    project.write_text(
        '[project]\ndependencies = ["httpx>=0.25", "packaging==24.0"]\n'
        '[tool.poetry.dependencies]\npython = "^3.11"\nfastapi = "^0.110"\n'
    )
    assert {item.name for item in parse_manifest(project)} == {"httpx", "packaging", "fastapi"}


def test_osv_cache_success_and_stale_fallback(tmp_path) -> None:
    cache = SQLiteCache(tmp_path / "osv.sqlite3")
    component = Component("demo", "1.0.0", "npm", "pkg:npm/demo@1.0.0")
    calls = 0

    async def successful_response(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(200, json={"vulns": [{"id": "GHSA-test"}]})

    async def verify() -> None:
        client = OsvClient(cache, transport=httpx.MockTransport(successful_response))
        result, stale = await client.lookup([component])
        assert result[0]["vulns"][0]["id"] == "GHSA-test"
        assert stale is False
        await client.lookup([component])
        assert calls == 1

        connection = sqlite3.connect(cache.path)
        try:
            connection.execute("UPDATE cache_entries SET expires_at = 0")
            connection.commit()
        finally:
            connection.close()
        assert cache.stats() == {"entries": 1, "expired": 1}

        async def offline_response(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("offline", request=request)

        offline_client = OsvClient(cache, transport=httpx.MockTransport(offline_response))
        stale_result, stale_used = await offline_client.lookup([component])
        assert stale_used is True
        assert stale_result[0]["vulns"][0]["id"] == "GHSA-test"

    asyncio.run(verify())
    assert cache.clear() == 1
    assert cache.stats() == {"entries": 0, "expired": 0}


def test_fixed_version_uses_installed_maintenance_branch() -> None:
    component = Component("Django", "2.2.0", "PyPI", "pkg:pypi/django@2.2.0")
    finding = _finding_from_osv(
        component,
        {
            "id": "GHSA-branch-test",
            "summary": "Branch-specific fix",
            "affected": [
                {
                    "package": {"name": "Django"},
                    "ranges": [
                        {"events": [{"introduced": "1.0"}, {"fixed": "1.11.23"}]},
                        {"events": [{"introduced": "2.0"}, {"fixed": "2.2.9"}]},
                        {"events": [{"introduced": "3.0"}, {"fixed": "3.2.4"}]},
                    ],
                }
            ],
        },
        stale=False,
    )
    assert finding.fixed_version == "2.2.9"
