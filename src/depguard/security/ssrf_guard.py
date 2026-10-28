"""Target validation and DNS-pinned resolution for URL scans."""

from __future__ import annotations

import ipaddress
import socket
from urllib.parse import SplitResult, urlsplit

from aiohttp.abc import AbstractResolver, ResolveResult


class TargetRejected(ValueError):
    """Raised when a scan target is malformed or outside the allowed network scope."""


def parse_target_url(value: str) -> SplitResult:
    """Validate URL syntax and return its parsed HTTP(S) components."""
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as exc:
        raise TargetRejected("Target URL has an invalid host or port") from exc
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise TargetRejected("Target must be an absolute HTTP or HTTPS URL")
    if parsed.username or parsed.password:
        raise TargetRejected("Credentials in target URLs are not permitted")
    if port is not None and not 1 <= port <= 65535:
        raise TargetRejected("Target port is outside the valid range")
    return parsed


def _address_allowed(value: str, allow_private: bool) -> bool:
    address = ipaddress.ip_address(value.split("%", 1)[0])
    blocked_metadata = {
        ipaddress.ip_address("169.254.169.254"),
        ipaddress.ip_address("100.100.100.200"),
        ipaddress.ip_address("fd00:ec2::254"),
    }
    if (
        address.is_multicast
        or address.is_unspecified
        or address.is_reserved
        or address.is_link_local
        or address in blocked_metadata
    ):
        return False
    return allow_private or address.is_global


class GuardedResolver(AbstractResolver):
    """Resolve hostnames once per connection and reject unsafe DNS answers."""

    def __init__(self, *, allow_private: bool = False) -> None:
        self.allow_private = allow_private

    async def resolve(
        self, host: str, port: int = 0, family: int = socket.AF_INET
    ) -> list[ResolveResult]:
        try:
            literal = ipaddress.ip_address(host)
            records = [(socket.AF_INET6 if literal.version == 6 else socket.AF_INET, str(literal))]
        except ValueError:
            try:
                results = (
                    await __import__("asyncio")
                    .get_running_loop()
                    .getaddrinfo(host, port, family=family, type=socket.SOCK_STREAM)
                )
            except OSError as exc:
                raise TargetRejected(f"Unable to resolve target host: {host}") from exc
            records = list(dict.fromkeys((item[0], item[4][0]) for item in results))
        if not records or any(
            not _address_allowed(address, self.allow_private) for _, address in records
        ):
            raise TargetRejected("Target resolves to a blocked network address")
        return [
            ResolveResult(
                hostname=host,
                host=address,
                port=port,
                family=address_family,
                proto=0,
                flags=socket.AI_NUMERICHOST,
            )
            for address_family, address in records
        ]

    async def close(self) -> None:
        """Close resolver resources; no persistent resources are held."""
