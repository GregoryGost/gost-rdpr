# Python cashews cache rules

Apply this rule when `CODEX_PROJECT.md` declares Python caching with `cashews` active, or when the task directly changes `cashews` setup, cached read paths, TTL, invalidation, or cache backend configuration.

This rule is the `cashews` cache profile. Do not apply it to `functools`, `cachetools`, direct Redis clients, NATS JetStream Key/Value, or another cache library unless the project has a separate rule for that library. Use `.codex/rules/python_nats_kv_cache.md` with `python-nats-kv-cache` for direct distributed caching through `nats-py` and NATS JetStream KV. Combine this rule with FastAPI, database, HTTP client, or testing skills only when those profiles are active.

## Required skills

Use together with:

- `python-core`;
- `python-cashews-cache`.

## Source of truth

Before changing cache behavior:

1. Read `CODEX_PROJECT.md` and confirm `Cache library: cashews`.
2. Check the `cashews` version, backend, settings, dependency policy, validation commands, and active Python profiles.
3. Inspect cached functions, callers, write paths, settings, tests, and deployment assumptions.
4. Use project-declared commands.

## Constraints

- Do not add caching mechanically.
- Cache only deterministic read behavior when bounded staleness is acceptable.
- Use explicit TTL and stable cache naming.
- Keep visibility scope in cache naming when the result depends on user, tenant, role, filters, pagination, locale, or feature flags.
- Cache serializable values, not live ORM entities or runtime resources.
- Invalidate after successful writes.
- Isolate cache state in tests.
