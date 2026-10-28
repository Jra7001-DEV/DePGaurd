"""Password hashing and login throttling helpers."""

from __future__ import annotations

import time
from collections import defaultdict, deque

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

password_hasher = PasswordHasher()
_failed_logins: dict[str, deque[float]] = defaultdict(deque)


def hash_password(password: str) -> str:
    """Hash a password with Argon2id defaults."""
    if len(password) < 12 or len(password) > 1024:
        raise ValueError("Password must be between 12 and 1024 characters")
    return password_hasher.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    """Verify a password hash without exposing parsing details."""
    try:
        return password_hasher.verify(password_hash, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def login_allowed(client_key: str, *, now: float | None = None) -> bool:
    """Allow at most ten failed login attempts in a rolling five-minute window."""
    timestamp = now or time.monotonic()
    attempts = _failed_logins[client_key]
    while attempts and attempts[0] < timestamp - 300:
        attempts.popleft()
    return len(attempts) < 10


def record_failed_login(client_key: str, *, now: float | None = None) -> None:
    """Record one failed login attempt."""
    _failed_logins[client_key].append(now or time.monotonic())
