# DePGuard Project Rules

- Use Python 3.11+, type hints, focused modules, and docstrings on public APIs.
- Keep scanning non-destructive: no exploitation, brute force, or denial-of-service behavior.
- Require explicit authorization before URL scans and guard against SSRF, including redirects.
- Never hardcode secrets; load configuration from environment variables.
- Keep CLI and API adapters thin; put business logic in reusable services.
- Validate untrusted inputs and uploads, use parameterized database queries, and avoid logging secrets.
- Add focused tests for new behavior and keep Ruff, Black, and mypy clean.