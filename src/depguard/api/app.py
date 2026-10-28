"""FastAPI application factory and middleware configuration."""

from __future__ import annotations

import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.base import RequestResponseEndpoint
from starlette.middleware.sessions import SessionMiddleware
from starlette.responses import Response

from depguard.api.routes import auth, scans
from depguard.config import get_settings
from depguard.db.seed import seed_roles

settings = get_settings()


@asynccontextmanager
async def lifespan(application: FastAPI) -> AsyncIterator[None]:
    """Initialize schema and built-in roles on first run."""
    del application
    seed_roles()
    yield


app = FastAPI(
    title="DePGuard API",
    version="0.1.0",
    docs_url="/docs",
    openapi_url="/openapi.json",
    lifespan=lifespan,
)
app.add_middleware(
    SessionMiddleware,
    secret_key=settings.secret_key,
    https_only=settings.cookie_secure,
    same_site="strict",
    session_cookie="depguard_session",
)
static_directory = os.path.join(os.path.dirname(__file__), "..", "web", "static")
app.mount("/static", StaticFiles(directory=static_directory), name="static")


@app.middleware("http")
async def security_headers(request: Request, call_next: RequestResponseEndpoint) -> Response:
    response = await call_next(request)
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self'; style-src 'self' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; frame-ancestors 'none'; base-uri 'self'"
    )
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    return response


@app.get("/health")
def health() -> dict[str, str]:
    """Return application liveness."""
    return {"status": "ok"}


@app.get("/")
def dashboard() -> FileResponse:
    """Serve the operational dashboard shell."""
    return FileResponse(os.path.join(static_directory, "index.html"))


app.include_router(auth.router, prefix="/api/v1/auth", tags=["auth"])
app.include_router(scans.router, prefix="/api/v1/scans", tags=["scans"])
