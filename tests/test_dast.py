"""Tests for passive DAST response inspection and SSRF boundary."""

from __future__ import annotations

import asyncio

import pytest
from multidict import CIMultiDict

from depguard.dast.scanner import _inspect_response, scan_url
from depguard.security.ssrf_guard import TargetRejected


def test_headers_cookies_cors_and_version_disclosure() -> None:
    headers = CIMultiDict()
    headers.add("Set-Cookie", "sid=secret")
    headers.add("Server", "nginx/1.2.3")
    headers.add("Access-Control-Allow-Origin", "*")
    headers.add("Access-Control-Allow-Credentials", "true")
    findings = _inspect_response(200, headers, b"body", "https")
    titles = {item.title for item in findings}
    assert "Missing content-security-policy header" in titles
    assert "Missing strict-transport-security header" in titles
    assert "Unsafe credentialed CORS policy" in titles
    assert "Version disclosure in server" in titles
    assert any("Cookie missing Secure" in title for title in titles)
    assert all("secret" not in item.evidence for item in findings)


def test_https_cookie_flags_and_large_body() -> None:
    headers = CIMultiDict({"Set-Cookie": "session=hidden; Secure; HttpOnly; SameSite=Lax"})
    findings = _inspect_response(200, headers, b"x" * 2_000_001, "https")
    assert not any(item.finding_type == "COOKIE" for item in findings)
    assert any("inspection limit" in item.title for item in findings)


def test_local_target_is_rejected_before_request() -> None:
    async def verify() -> None:
        with pytest.raises(TargetRejected):
            await scan_url("http://127.0.0.1:8080")

    asyncio.run(verify())


def test_local_http_response_is_inspected_safely() -> None:
    async def verify() -> None:
        async def handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            await reader.readline()
            while await reader.readline() not in {b"\r\n", b"\n", b""}:
                pass
            writer.write(
                b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n"
                b"Set-Cookie: session=private-value\r\nConnection: close\r\n\r\nok"
            )
            await writer.drain()
            writer.close()
            await writer.wait_closed()

        server = await asyncio.start_server(handler, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        try:
            findings = await scan_url(f"http://127.0.0.1:{port}", allow_private=True)
            assert any(item.finding_type == "COOKIE" for item in findings)
            assert all("private-value" not in item.evidence for item in findings)
        finally:
            server.close()
            await server.wait_closed()

    asyncio.run(verify())
