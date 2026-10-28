"""Idempotent base-role seeding."""

from sqlalchemy import select

from depguard.db.models import Role
from depguard.db.session import SessionLocal, init_db


def seed_roles() -> None:
    """Create the standard roles if they do not already exist."""
    init_db()
    with SessionLocal.begin() as session:
        existing = set(session.scalars(select(Role.role_name)).all())
        for role_name in ("User", "Analyst", "Admin"):
            if role_name not in existing:
                session.add(Role(role_name=role_name))
