# Testing Against Local Labs

Only scan deliberately deployed applications on an isolated local Docker network. Do not expose vulnerable lab containers to the public internet.

1. Start a lab application such as OWASP Juice Shop or DVWA on a private Docker network.
2. Set `DEPGUARD_ALLOW_PRIVATE_TARGETS=true` for the DePGuard process. This does not allow link-local or cloud metadata addresses.
3. Sign in to the dashboard or run `depguard scan url http://127.0.0.1:<published-port> --profile quick --auth-confirm`.
4. Review missing headers, cookie attributes, and version disclosures. The current quick scanner performs one GET; crawler and active probe profiles are not implemented.
5. Stop and remove the lab container and unset the private-target override after testing.

bWAPP and DVWA intentionally contain vulnerable functionality. Use passive checks only until a future version implements carefully scoped, opt-in safe probes.
