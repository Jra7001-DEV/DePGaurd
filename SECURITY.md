# Security Policy

DePGuard is intended for systems you own or are explicitly authorized to assess. URL scanning requires an authorization confirmation and is non-destructive. Private, loopback, link-local, and metadata destinations are denied by default; `DEPGUARD_ALLOW_PRIVATE_TARGETS=true` is for isolated labs only and still blocks link-local/metadata addresses.

Please do not include credentials, cookies, or sensitive target data in public issue reports. Report suspected DePGuard vulnerabilities privately to the repository maintainers. Until a security contact is configured, use a private repository issue and share only the minimum reproduction details.

Deploy behind HTTPS, configure a strong random `DEPGUARD_SECRET_KEY`, set `DEPGUARD_COOKIE_SECURE=true`, and restrict network access to the service. DePGuard is an aid to review, not a substitute for professional security testing.
