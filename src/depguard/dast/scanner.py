"""Bounded HTTP checks for an explicitly authorized web target."""

from __future__ import annotations

import http.cookies
from collections.abc import Mapping
from urllib.parse import urlunsplit

import aiohttp

from depguard.models import Finding, Severity
from depguard.risk.engine import score_finding
from depguard.security.ssrf_guard import GuardedResolver, TargetRejected, parse_target_url

MAX_RESPONSE_BYTES = 2_000_000


async def scan_url(
    target_url: str,
    *,
    allow_private: bool = False,
    timeout_seconds: float = 10.0,
    headers: dict[str, str] | None = None,
) -> list[Finding]:
    """Fetch one target page and report passive headers, cookies, and disclosures."""
    parsed = parse_target_url(target_url)
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    resolver = GuardedResolver(allow_private=allow_private)
    await resolver.resolve(parsed.hostname or "", port)
    connector = aiohttp.TCPConnector(resolver=resolver, use_dns_cache=False, ssl=True, limit=1)
    timeout = aiohttp.ClientTimeout(total=timeout_seconds, connect=min(timeout_seconds, 5.0))
    request_url = urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", parsed.query, ""))
    try:
        async with aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            trust_env=False,
            headers=headers or {},
        ) as session:
            async with session.get(request_url, allow_redirects=False) as response:
                body = await response.content.read(MAX_RESPONSE_BYTES + 1)
                findings = _inspect_response(response.status, response.headers, body, parsed.scheme)
                for finding in findings:
                    score_finding(finding, internet_exposed=not allow_private)
                return findings
    except TargetRejected:
        raise
    except aiohttp.ClientSSLError as exc:
        findings = [
            Finding(
                title="TLS certificate verification failed",
                severity=Severity.HIGH,
                finding_type="TLS",
                evidence=f"{type(exc).__name__}: {str(exc)[:240]}",
                remediation="Install a trusted, valid certificate for the target hostname.",
            )
        ]
        for finding in findings:
            score_finding(finding, internet_exposed=not allow_private)
        return findings
    except (aiohttp.ClientError, TimeoutError) as exc:
        findings = [
            Finding(
                title="Target connection failed",
                severity=Severity.INFO,
                finding_type="DISCLOSURE",
                evidence=f"{type(exc).__name__}: {str(exc)[:240]}",
                remediation="Verify target availability and TLS certificate configuration.",
            )
        ]
        for finding in findings:
            score_finding(finding, internet_exposed=not allow_private)
        return findings


def _inspect_response(
    status: int, headers: Mapping[str, str], body: bytes, scheme: str
) -> list[Finding]:
    """Inspect response metadata without reflecting or submitting input."""
    del status
    header_values = {str(key).lower(): str(value) for key, value in headers.items()}
    findings: list[Finding] = []

    def missing_header(name: str, severity: Severity, remediation: str) -> None:
        if name not in header_values:
            findings.append(
                Finding(
                    title=f"Missing {name} header",
                    severity=severity,
                    finding_type="HEADER",
                    evidence=f"Response does not include {name}.",
                    remediation=remediation,
                )
            )

    missing_header(
        "content-security-policy", Severity.MEDIUM, "Define a restrictive Content-Security-Policy."
    )
    if scheme == "https":
        missing_header(
            "strict-transport-security", Severity.MEDIUM, "Enable HSTS with a suitable max-age."
        )
    if (
        "x-frame-options" not in header_values
        and "frame-ancestors" not in header_values.get("content-security-policy", "").lower()
    ):
        findings.append(
            Finding(
                "Missing clickjacking protection",
                Severity.MEDIUM,
                "HEADER",
                "Neither X-Frame-Options nor CSP frame-ancestors is present.",
                "Set X-Frame-Options or a restrictive CSP frame-ancestors directive.",
            )
        )
    missing_header("x-content-type-options", Severity.LOW, "Set X-Content-Type-Options: nosniff.")
    missing_header("referrer-policy", Severity.LOW, "Set a privacy-preserving Referrer-Policy.")

    cors_origin = header_values.get("access-control-allow-origin", "")
    cors_credentials = header_values.get("access-control-allow-credentials", "").lower()
    if cors_origin == "*" and cors_credentials == "true":
        findings.append(
            Finding(
                "Unsafe credentialed CORS policy",
                Severity.HIGH,
                "HEADER",
                "Access-Control-Allow-Origin is '*' while credentials are enabled.",
                "Allow only explicitly trusted origins and review credential requirements.",
            )
        )

    cookie_headers = [value for key, value in headers.items() if str(key).lower() == "set-cookie"]
    for raw_cookie in cookie_headers:
        cookie = http.cookies.SimpleCookie()
        try:
            cookie.load(raw_cookie)
        except http.cookies.CookieError:
            continue
        for name, morsel in cookie.items():
            flags = []
            if scheme == "https" and not morsel["secure"]:
                flags.append("Secure")
            if not morsel["httponly"]:
                flags.append("HttpOnly")
            if not morsel["samesite"]:
                flags.append("SameSite")
            for flag in flags:
                findings.append(
                    Finding(
                        title=f"Cookie missing {flag}: {name}",
                        severity=Severity.MEDIUM if flag == "Secure" else Severity.LOW,
                        finding_type="COOKIE",
                        evidence=f"Set-Cookie attributes for {name} omit {flag}; value redacted.",
                        remediation=(
                            f"Set the {flag} attribute where compatible with application behavior."
                        ),
                    )
                )

    for header in ("server", "x-powered-by"):
        value = header_values.get(header)
        if value and any(character.isdigit() for character in value):
            findings.append(
                Finding(
                    title=f"Version disclosure in {header}",
                    severity=Severity.LOW,
                    finding_type="DISCLOSURE",
                    evidence=f"{header}: {value[:120]}",
                    remediation="Remove or generalize server and framework version headers.",
                )
            )
    if len(body) > MAX_RESPONSE_BYTES:
        findings.append(
            Finding(
                "Response exceeded inspection limit",
                Severity.INFO,
                "DISCLOSURE",
                f"The response body exceeded {MAX_RESPONSE_BYTES} bytes; remaining content "
                "was not read.",
                "No action is required; the scanner intentionally limits response processing.",
            )
        )
    return findings
