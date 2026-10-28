"""Tests for target validation and password handling."""

import asyncio

import pytest

from depguard.security.auth import hash_password, verify_password
from depguard.security.ssrf_guard import GuardedResolver, TargetRejected, parse_target_url


def test_target_url_rejects_non_http_and_credentials() -> None:
    with pytest.raises(TargetRejected):
        parse_target_url("file:///etc/passwd")
    with pytest.raises(TargetRejected):
        parse_target_url("https://user:pass@example.com")


def test_private_ip_denied_and_lab_override_allowed() -> None:
    async def verify() -> None:
        with pytest.raises(TargetRejected):
            await GuardedResolver().resolve("127.0.0.1", 80)
        accepted = await GuardedResolver(allow_private=True).resolve("127.0.0.1", 80)
        assert accepted[0]["host"] == "127.0.0.1"

    asyncio.run(verify())


def test_password_hashing() -> None:
    hashed = hash_password("a-long-password-for-tests")
    assert verify_password("a-long-password-for-tests", hashed)
    assert not verify_password("wrong-password", hashed)
    with pytest.raises(ValueError):
        hash_password("short")
