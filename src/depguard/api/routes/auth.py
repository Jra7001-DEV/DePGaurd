"""Registration, login, and session endpoints."""

from __future__ import annotations

import re

from fastapi import APIRouter, Depends, Header, HTTPException, Request, Response
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from depguard.db.models import AuditLog, Role, User
from depguard.db.session import get_session
from depguard.security.auth import (
    hash_password,
    login_allowed,
    record_failed_login,
    verify_password,
)

router = APIRouter()


class Credentials(BaseModel):
    username: str = Field(min_length=3, max_length=80)
    password: str = Field(min_length=12, max_length=1024)


class Registration(Credentials):
    email: str = Field(min_length=5, max_length=254)


@router.post("/register", status_code=201)
def register(
    details: Registration,
    request: Request,
    session: Session = Depends(get_session),
) -> dict[str, str]:
    """Register a standard user; elevated roles require an administrator."""
    if not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", details.email):
        raise HTTPException(status_code=422, detail="Invalid email address")
    existing = session.scalar(
        select(User).where((User.username == details.username) | (User.email == details.email))
    )
    if existing:
        raise HTTPException(status_code=409, detail="Username or email is already registered")
    role = session.scalar(select(Role).where(Role.role_name == "User"))
    if role is None:
        raise HTTPException(status_code=503, detail="Role configuration is unavailable")
    user = User(
        username=details.username,
        email=details.email,
        password_hash=hash_password(details.password),
        role_id=role.role_id,
    )
    session.add(user)
    session.flush()
    session.add(
        AuditLog(user_id=user.user_id, action="user.register", ip_address=_client_ip(request))
    )
    session.commit()
    return {"status": "registered"}


@router.post("/login")
def login(
    details: Credentials,
    request: Request,
    response: Response,
    session: Session = Depends(get_session),
) -> dict[str, str]:
    """Authenticate a user and create a signed session plus CSRF token."""
    client_key = _client_ip(request)
    if not login_allowed(client_key):
        raise HTTPException(status_code=429, detail="Too many login attempts")
    user = session.scalar(select(User).where(User.username == details.username))
    if (
        user is None
        or not user.is_active
        or not verify_password(details.password, user.password_hash)
    ):
        record_failed_login(client_key)
        raise HTTPException(status_code=401, detail="Invalid username or password")
    request.session.clear()
    request.session["user_id"] = user.user_id
    request.session["csrf"] = __import__("secrets").token_urlsafe(32)
    session.add(AuditLog(user_id=user.user_id, action="user.login", ip_address=client_key))
    session.commit()
    return {"status": "authenticated", "csrf_token": request.session["csrf"]}


@router.post("/logout")
def logout(
    request: Request,
    response: Response,
    csrf_token: str | None = Header(default=None, alias="X-CSRF-Token"),
) -> dict[str, str]:
    """Clear the current browser session."""
    if not request.session.get("user_id") or csrf_token != request.session.get("csrf"):
        raise HTTPException(status_code=403, detail="CSRF token missing or invalid")
    request.session.clear()
    response.delete_cookie("depguard_session")
    return {"status": "logged_out"}


@router.get("/me")
def current_user(request: Request, session: Session = Depends(get_session)) -> dict[str, str]:
    """Return the authenticated user's identity and role."""
    user_id = request.session.get("user_id")
    user = session.get(User, user_id) if user_id else None
    if user is None or not user.is_active:
        raise HTTPException(status_code=401, detail="Authentication required")
    return {
        "username": user.username,
        "role": user.role.role_name,
        "csrf_token": request.session.get("csrf", ""),
    }


def _client_ip(request: Request) -> str:
    """Return the direct peer address without trusting forwarded headers."""
    return request.client.host if request.client else "unknown"
