# Security Review Checklist

Use this checklist before finishing a security-sensitive backend change or review.

- [ ] Source, settings, tests, and existing conventions were inspected before changing behavior.
- [ ] Trust boundaries are explicit: request, auth context, service/policy, repository/DB, outbound HTTP, filesystem, cache, logs, and errors.
- [ ] Authentication uses the existing repository scheme; token/session presence, expiration, issuer, audience, and scope are validated where applicable.
- [ ] Authorization is enforced in service/domain/policy code, not only routers.
- [ ] Object-level operations check tenant, user, ownership, and permission state.
- [ ] List queries enforce visibility in query predicates instead of post-fetch filtering.
- [ ] Missing or ambiguous user, role, scope, tenant, or owner state denies by default.
- [ ] Client-provided `tenant_id`, `user_id`, role, status, price, ownership, and permission fields are not trusted.
- [ ] Input bounds cover lengths, counts, pagination, numeric ranges, date ranges, enum values, file size, and response-size-affecting inputs.
- [ ] User-controlled SQL values use SQLAlchemy expressions or bound parameters.
- [ ] Dynamic `ORDER BY`, column, table, and direction inputs use allowlists.
- [ ] Repository methods execute or `flush()` where required to detect expected constraint and persistence failures.
- [ ] Repository methods translate expected `IntegrityError`, `DBAPIError`, and driver exceptions to stable repository/domain errors with exception chaining.
- [ ] Services, routers, and API layers do not import or catch raw SQLAlchemy or driver exceptions.
- [ ] Public API errors are produced from typed repository/domain errors rather than directly from persistence exceptions.
- [ ] Raw DB errors, SQL, constraint names, schema details, connection details, stack traces, internal URLs, and file paths are not exposed to clients.
- [ ] Database-specific safety checks from the active database skill are applied.
- [ ] SQLite `PRAGMA foreign_keys=ON` is centralized and tested when the active project database is SQLite.
- [ ] User-controlled file and DB paths are normalized, constrained to an allowed base directory, and reject traversal.
- [ ] User-controlled URLs are scheme/host allowlisted and block localhost, loopback, private, link-local, metadata, and internal targets.
- [ ] Redirect targets are re-validated and internal auth headers are not forwarded to user-controlled hosts.
- [ ] HTTPX calls have explicit timeouts and response size limits where content size matters.
- [ ] CORS does not combine wildcard origins with credentials and does not act as authorization.
- [ ] Secrets live in settings/secret providers, not source, fixtures, logs, cache keys, or error responses.
- [ ] Logs redact `Authorization`, `Cookie`, `Set-Cookie`, tokens, passwords, API keys, personal data where applicable, and unsafe payloads.
- [ ] Cache keys include tenant/user/permission scope when visibility depends on them.
- [ ] Authenticated or permission-filtered responses are not cached unless scope, TTL, and invalidation are explicit.
- [ ] Rate limiting uses a supported project mechanism or was explicitly requested.
- [ ] New dependencies are justified, maintained, and constrained according to project policy.
- [ ] Security regression tests cover unauthorized, forbidden, tenant/object isolation, invalid input boundaries, SQL injection attempts, repository error translation, absence of raw persistence exceptions outside repositories, client-safe API mapping, SSRF rejection, CORS config changes, secret redaction, path traversal, and cache scope gaps where relevant.
- [ ] Code review applied `python-core`, `python-testing`, and every relevant specialist skill for the touched backend area.
