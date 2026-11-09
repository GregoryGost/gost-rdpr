---
name: python-cashews-cache
description: "Use for cashews cache design, keys, TTL, invalidation, backend lifecycle, testing, and FastAPI integration."
---

# Python Cashews Cache

Use this skill when `CODEX_PROJECT.md` declares `Cache library: cashews`, or when a task directly changes `cashews` setup, cached read paths, TTL, invalidation, or cache backend configuration.

This skill is the `cashews` cache profile. Do not apply it to `functools`, `cachetools`, direct Redis clients, NATS JetStream Key/Value, or another cache library unless the project has a separate skill for that library. Use `python-nats-kv-cache` for direct distributed caching through `nats-py` and NATS JetStream KV. This skill can be combined with FastAPI, database, HTTP client, or testing skills when those profiles are active.

Apply `.codex/rules/python_cashews_cache.md`, `python-core`, and this skill together.

When FastAPI is active, also apply `python-fastapi-expert` for app lifespan, middleware, dependency, and API contract concerns. Keep cache policy here and FastAPI routing/API policy in `python-fastapi-expert`.

Load references when needed:

- `references/patterns-and-review.md` for cache decision, key scope, invalidation, FastAPI wiring, and tests.
- `references/official-sources.md` for `cashews` and framework documentation links.

## Workflow

1. Read `CODEX_PROJECT.md` and confirm `Cache library: cashews`.
2. Confirm the `cashews` version, backend, settings, dependency policy, validation commands, and active Python overlays.
3. Confirm the dependency source of truth and existing `cashews` dependency version from repository metadata before changing cache behavior.
4. Inspect cached functions, callers, write paths, settings, tests, and deployment assumptions.
5. Decide whether the read path is deterministic and whether bounded staleness is acceptable.
6. Define TTL, key scope, invalidation triggers, backend, and test coverage before adding cache behavior.
7. Run or report project-declared validation commands.

## Guardrails

- Do not add caching mechanically.
- Do not use cache behavior before a cache backend and lifecycle owner are declared in project settings/configuration or `CODEX_PROJECT.md`.
- Prefer service/domain read methods for business data caching.
- Keep routers and HTTP handlers free of cache decisions unless HTTP cache semantics are the explicit task.
- Use stable cache names that include all visibility-affecting inputs.
- Cache serializable DTOs, schemas, dataclasses, dictionaries, or scalar values.
- Do not cache live ORM entities, sessions, connections, requests, responses, or process-local runtime objects.
- Invalidate after successful writes.
- Treat TTL as a fallback, not the primary consistency mechanism for mutable data.
- Use isolated cache backends or cleanup in tests.
- Use production-safe shared backends for multi-worker deployments.

## Review Checklist

- [ ] `Cache library: cashews` is active in `CODEX_PROJECT.md` or `cashews` is directly touched by the task.
- [ ] The `cashews` version, backend, lifecycle owner, and dependency source of truth were checked.
- [ ] Cached operation is deterministic and read-oriented.
- [ ] TTL and cache naming are explicit.
- [ ] Visibility scope is included in cache naming when needed.
- [ ] Cached value is serializable and detached from live resources.
- [ ] Write paths invalidate after success.
- [ ] Tests cover miss, hit, invalidation, and scoped values.
- [ ] If FastAPI is active, app wiring and API behavior were reviewed with `python-fastapi-expert`.
