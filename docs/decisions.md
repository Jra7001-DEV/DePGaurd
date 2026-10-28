# Design Decisions

- URL scanning always requires explicit authorization and does not follow redirects. This minimizes accidental scope expansion and SSRF risk.
- Private-target scanning is disabled by default; isolated lab use requires an explicit environment override.
- OSV is used first for ecosystem-aware matching. NVD/CVE.org enrichment is deferred until provider-specific rate limits, response parsing, and attribution are covered by tests.
- Login uses signed browser sessions with a CSRF token rather than exposing bearer credentials to the static dashboard.
- Manifest scanning accepts bounded input files and does not install dependencies. Include paths in requirements manifests remain confined to the initial manifest directory.
