# User Guide

## Local setup

Use Python 3.11 or newer. Install with `python -m pip install -e '.[dev]'`, initialize roles with `depguard db seed`, then create an administrator using `depguard user create admin admin@example.test`. Start the service with `depguard serve`; open `http://127.0.0.1:8000`.

## Dependency scan

Run `depguard scan manifest examples/package.json examples/requirements.txt --sbom cyclonedx --report pdf`. The scanner reads manifests only; it never installs or executes dependencies. Use `--offline` to use local cache data without network access. The current supported output includes CycloneDX 1.5 JSON and PDF.

## URL scan

Use `depguard scan url https://your-authorized-host.example --profile quick --auth-confirm`. URL scans make one bounded GET and do not follow redirects. Local/private destinations are denied by default. For a purpose-built isolated lab, set `DEPGUARD_ALLOW_PRIVATE_TARGETS=true` explicitly.

## API

Open `/docs` for the FastAPI OpenAPI interface. Register a standard account at `/api/v1/auth/register`, sign in to receive a session and CSRF token, then submit authorized URL scans through `/api/v1/scans` using `X-CSRF-Token`.

## Cache

Use `depguard cache stats`, `depguard cache update <manifest>`, and `depguard cache clear`. Cached advisories are stored in the user's local cache directory by default.
