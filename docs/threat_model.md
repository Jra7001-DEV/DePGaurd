# Threat Model

| STRIDE | Threat | Mitigation | Residual risk |
| --- | --- | --- | --- |
| Spoofing | Unauthorized dashboard access | Argon2id passwords, signed sessions, login throttling | Account recovery and MFA are not implemented |
| Tampering | Forged state-changing browser requests | SameSite strict session cookie and CSRF token checks | Deployment must use TLS and a strong session secret |
| Repudiation | User denies authorizing a scan | Authorization confirmation is stored in the audit log with user, target, time, and peer IP | Audit export and immutable retention are not implemented |
| Information disclosure | Secrets or findings leak through responses/logs | Password hashes only, cookie values redacted, HTTPS-only deployment guidance | Admin/audit UI and log redaction tests are incomplete |
| Denial of service | Large manifests or aggressive scan requests | 2 MB manifest bound, bounded HTTP timeouts, one URL request, OSV concurrency limit | Global/per-host request quotas and login state persistence are incomplete |
| Elevation of privilege | Cross-user scan access or role manipulation | API queries scope scans to the authenticated user; registration grants only User | Complete server-side RBAC/admin endpoints are not implemented |

URL scanning is a powerful capability and is explicitly gated by authorization. DNS answers are validated and pinned through a custom resolver; redirects and environment proxies are disabled. Keep the service on a trusted network and enable private-target access only for isolated lab environments.
