---
name: python-httpx-client
description: "Use for Python HTTPX clients with httpx-retries: lifecycle, timeouts, retries, rate limits, streaming, SSRF, and tests."
---

# Python HTTPX Client

Apply this skill when creating, changing, reviewing, or testing outgoing HTTP clients based on `httpx` and the already selected `httpx-retries` retry layer.

## Required Dependencies

- `python-core`

## Optional Coordination

Apply additional active skills only when the task touches their area:

- `python-testing` for pytest policy, fixtures, mocks/fakes, coverage, retry tests, and integration-client regression tests.
- `python-fastapi-expert` when FastAPI lifespan, dependency injection, routing, services, or application shutdown own the client lifecycle.
- The active database skill from `CODEX_PROJECT.md` when outbound HTTP behavior interacts with transactions, repositories, or persistence.
- `python-backend-security` when user-influenced URLs, redirects, callbacks, webhooks, proxy-like fetches, credentials, logging, or SSRF risk are in scope.

Read `CODEX_PROJECT.md` and repository metadata before changing HTTP client behavior. Confirm the active HTTP client library, retry layer, dependency versions, dependency source of truth, timeout policy, and project-declared validation commands.

Use this skill for FastAPI features only when the feature calls an external HTTP API. Do not use it for inbound FastAPI routing unless outbound HTTP behavior is part of the work.

For concrete bad/good examples and a compact review checklist, read `references/patterns-and-review.md` when implementing or reviewing an integration client.

## Review Workflow

When reviewing an HTTPX integration client:

- Confirm the required `python-core` dependency and apply `python-testing` when tests or test policy are in scope.
- Inspect the client implementation, settings, dependency wiring, lifecycle/shutdown code, and nearby tests before proposing changes.
- Verify that the client has a single clear owner for `base_url`, timeout, limits, transport, SSL, proxy, auth, `httpx-retries` retry, rate-limit, and `trust_env` policy.
- Check that hot-path code does not instantiate `AsyncClient` per request or per operation.
- Check that outbound HTTP details stay inside integration clients or services, not routers.
- Check that external HTTP calls are not executed while a DB write transaction is open.
- Check that errors are mapped at the integration boundary and do not leak raw `httpx` exceptions, secrets, tokens, cookies, or sensitive payloads.
- Check that user-influenced URLs have scheme, host, redirect, and network-target validation.
- Check that streaming responses are closed and bounded where response size matters.
- Check that rate-limit handling, retry budget, `Retry-After`, and final failure mapping are centralized and tested.
- Check that tests use local transports, fake servers, or project-approved provider sandboxes instead of real uncontrolled external APIs.
- Review tests together with code changes. Do not approve an HTTPX client change when important success, failure, timeout, retry, rate-limit, SSRF, logging, or cleanup behavior is untested.

## Client Lifecycle

- Reuse a managed `httpx.AsyncClient`; do not create a new client inside every hot-path function or request.
- Prefer one managed client per integration, FastAPI lifespan, DI provider, or explicit client factory.
- Always close clients with `aclose()` or an async context manager when the lifecycle is local.
- Do not use module-level clients without clear lifecycle and shutdown ownership.
- Use separate clients when `base_url`, auth, proxy, mTLS, limits, timeout, retry, or rate-limit policies materially differ.
- Treat named clients as immutable configuration objects. If a client name already exists, do not silently return it for a different `base_url`, timeout, auth, limits, SSL, proxy, retry, rate-limit, or `trust_env` policy; either reject the conflicting configuration or use a distinct client name/profile.
- Decide `trust_env` explicitly. For controlled backend integrations, prefer `trust_env=False` unless proxy, SSL certificate, or environment-driven behavior is intentionally required.
- Keep client lifecycle shutdown wired into the application lifespan or explicit shutdown hook; a factory that stores clients must also provide and use a close method.

## Timeout Policy

- Every outbound call must have an explicit timeout policy.
- Define integration-level defaults with `httpx.Timeout(connect=..., read=..., write=..., pool=...)`.
- Allow narrower per-call overrides only when the call contract requires them.
- Avoid `timeout=None` in application runtime paths.
- Treat pool timeout as part of backpressure; a pool timeout is not the same failure as an upstream read timeout.
- Do not expose ad-hoc per-call timeout overrides from a shared client factory unless the override is part of a named integration profile. A repeated request for the same named client with different timeout values must not be silently ignored.
- Avoid partial timeout configuration. Prefer explicit `connect`, `read`, `write`, and `pool` values in settings or integration profiles.
- Do not rely on retries to compensate for missing or overly long timeouts. Timeouts bound one attempt; `httpx-retries` attempt count and `total_timeout` bound retry behavior.

## Resource Control

- Configure `httpx.Limits` for high-traffic or shared clients.
- Treat `httpx.Limits` as connection-pool control, not as request-per-second, per-minute, per-user, per-token, or quota enforcement.
- Prevent unbounded parallel calls to the same upstream.
- Use existing project-owned throttling, semaphores, queues, or rate-limit mechanisms when the upstream documents request-per-second, per-minute, per-user, per-token, or quota constraints.
- Do not add a new rate-limit dependency from this skill. If no project rate-limit mechanism exists and the upstream requires proactive throttling, surface that as a design decision for the user.
- Use separate clients and separate project-owned limiters for materially different upstreams or traffic classes so that a slow or throttled integration cannot starve unrelated integrations.
- Watch for connection-pool starvation when long streaming reads share a client with ordinary JSON calls.
- Keep integration-specific limits in settings or explicit factory parameters, not scattered call sites.
- If a custom `HTTPTransport` or `AsyncHTTPTransport` is created manually and wrapped by `RetryTransport`, configure resource limits at the transport layer that owns the connection pool.
- Prefer a single factory/profile object that owns timeout, limits, transport, SSL, proxy, `trust_env`, `httpx-retries` retry, and rate-limit settings together.

## HTTPX And httpx-retries Responsibility Split

Use only the selected libraries for the HTTP client layer: `httpx` and `httpx-retries`. Do not introduce additional retry, rate-limit, or circuit-breaker dependencies from this skill.

HTTPX owns:

- `AsyncClient` lifecycle and connection pooling;
- `Timeout` with `connect`, `read`, `write`, and `pool` values;
- `Limits` for connection-pool control;
- `trust_env` behavior;
- streaming response lifecycle through `async with client.stream(...)`;
- HTTP exception types and response objects;
- low-level transport configuration.

`httpx-retries` owns HTTP retry mechanics:

- `RetryTransport` wrapping the HTTPX transport;
- retryable HTTP methods through `allowed_methods`;
- retryable status codes through `status_forcelist`, including `429`, `502`, `503`, and `504` when configured;
- retryable HTTPX exceptions through `retry_on_exceptions`;
- `Retry-After` handling through `respect_retry_after_header`;
- exponential backoff through `backoff_factor`;
- jitter through `backoff_jitter`;
- single-sleep cap through `max_backoff_wait`;
- cumulative retry sleep cap through `total_timeout`.

The integration client still owns:

- deciding which upstream operations are safe to retry;
- idempotency rules, especially for `POST`, payment, mutation, or enqueue operations;
- final error mapping after `httpx-retries` exhausts retries and returns or raises the final outcome;
- preserving safe `retry_after` metadata when a final `429` is returned;
- proactive quota handling when the upstream publishes request-rate or quota limits;
- observability: sanitized logs, metrics, retry attempt visibility, and upstream request IDs;
- avoiding long blocking waits in request-handling paths;
- tests for retryable and non-retryable behavior.

## Retry Policy With httpx-retries

- Use `httpx-retries.RetryTransport` as the default retry layer for HTTPX request/response retry policies.
- Configure `httpx_retries.Retry` explicitly for production integrations. Do not rely on implicit defaults when idempotency, `Retry-After`, retry status codes, max attempts, max backoff, jitter, or total timeout affect the contract.
- Keep `allowed_methods` explicit. Retry safe methods by default: usually `GET`, `HEAD`, and `OPTIONS`; include `PUT` or `DELETE` only when the upstream contract makes them idempotent for the operation.
- Retry `POST` only when the operation has an idempotency key, deduplication key, or documented upstream guarantee. Put the idempotency key into the request headers or body according to the upstream contract.
- Keep `status_forcelist` explicit. Include only statuses the integration is allowed to retry, commonly `429`, `502`, `503`, and `504`.
- Keep `retry_on_exceptions` explicit for production-critical integrations. Do not retry broad exception types that can hide programming errors or validation bugs.
- Use `respect_retry_after_header=True` when `429` or overload responses are retryable for the integration.
- Configure `backoff_factor`, `backoff_jitter`, `max_backoff_wait`, and `total_timeout` to prevent retry storms and unbounded sleep.
- Do not combine `httpx-retries` with `HTTPTransport(retries=...)` or `AsyncHTTPTransport(retries=...)` for the same failure mode. Prefer one retry owner: `RetryTransport`.
- Do not stack integration retries, service retries, task retries, and queue retries for the same failure mode unless the layering is explicitly documented.
- After retries are exhausted, map the final response or exception to a typed integration/domain error at the client boundary.

## Fault Tolerance, Rate Limits, And 429 Handling

- Define a per-upstream resilience profile for important integrations: timeout policy, connection limits, concurrency limits, project-owned rate-limit policy, `httpx-retries` retry policy, `429` handling, error mapping, and observability.
- Do not confuse connection limits with rate limits. Connection limits bound the connection pool; rate limits bound request throughput or quota consumption.
- Enforce known upstream quotas proactively with existing project mechanisms instead of relying only on receiving `429`.
- Treat `429 Too Many Requests` as a first-class integration outcome, not as a generic non-2xx failure.
- Let `httpx-retries` handle retryable `429` responses when the operation is retryable and the `Retry` policy includes `429` in `status_forcelist`.
- Configure `total_timeout` and `max_backoff_wait` so large or repeated `Retry-After` values cannot block the request path beyond the accepted retry budget.
- If a final `429` remains after retries are exhausted, raise or return a typed rate-limit error that preserves sanitized `retry_after` metadata for the caller when safe.
- If the upstream returns `RateLimit-*`, `X-RateLimit-*`, or vendor quota headers, parse them only when the upstream contract documents their semantics.
- Do not implement long sleeps in application request handlers. If the retry window is too long for the request path, surface a typed retry-later/rate-limit outcome or delegate to existing project queue/scheduling mechanisms.
- Avoid fallback behavior unless it is explicitly accepted by the business contract. Stale or cached fallback data must be labeled and bounded.

## Error Boundary

- Convert `httpx` and `httpx-retries` outcomes into integration or domain errors at the client boundary.
- Distinguish timeout, network, protocol, rate-limit, non-2xx response, invalid JSON/schema, and business-level upstream errors.
- Preserve useful context: integration name, method, sanitized URL path, status code, request id, attempt count when available, safe `retry_after` metadata, and stable upstream error code when available.
- Do not leak raw `httpx` exceptions into API responses unless the project explicitly defines that contract.
- Do not log raw auth headers, tokens, cookies, credentials, or sensitive payloads.
- Do not collapse all upstream failures into one generic exception when the caller needs different handling for timeout, rate-limit, unavailable, forbidden, not-found, or invalid-upstream-response cases.

## Request Construction

- Prefer `base_url` and relative paths for fixed upstream integrations.
- Use `params`, `json`, `content`, and `files` according to HTTPX semantics; do not hand-build query strings or JSON bodies.
- Prefer typed request and response DTOs or Pydantic schemas at the integration boundary.
- Validate and normalize externally supplied URL or path components before calling HTTPX.
- Never build external URLs by unsafe string concatenation.
- Keep redirect behavior explicit. Do not enable `follow_redirects=True` for user-influenced URLs unless every redirect target is re-validated against the same scheme, host, and network allowlist.
- Do not attach default internal credentials to requests whose final host can be influenced by user input or redirects.

## SSRF And URL Safety

- Reject user-controlled arbitrary URLs by default.
- Allow only `http` and `https` unless a documented integration requires another scheme.
- Enforce host allowlists for callbacks, fetchers, webhooks, preview generators, importers, and proxy-like features.
- Block localhost, loopback, link-local, private network ranges, metadata IPs, and internal DNS targets when fetching user-provided URLs.
- Re-validate final redirect targets before sending credentials or trusting content.
- Never send internal credentials to user-controlled domains.
- URL allowlists must validate the normalized hostname, effective port, scheme, and resolved network target when user input can influence the URL.
- Host allowlists alone are not enough for generic fetchers when DNS rebinding, redirects, or private network resolution are possible.
- Re-validate after DNS resolution and after each redirect when redirects are allowed.

## Streaming

- Use `async with client.stream(...)` for streaming responses.
- Always close response objects.
- Do not read unbounded response bodies into memory.
- Set maximum accepted response size where content size matters.
- Handle partial reads, cancellation, and downstream disconnects deliberately.
- Do not return raw `httpx.Response` outside the integration boundary unless the response lifecycle is explicit and tested.

## FastAPI Integration

- Provide clients through lifespan, dependency injection, or a dedicated factory; do not construct them ad hoc in routes.
- Keep HTTPX details out of routers. Routes call services; services call integration clients.
- Avoid external HTTP calls inside DB write transactions.
- Use the project queue or worker mechanism for durable or retry-later work instead of FastAPI `BackgroundTasks`.
- Keep auth, timeout, retry, limits, base URL, rate-limit, and error mapping policy owned by the integration client or its factory.

## Testing

- Follow `python-testing` for pytest structure, assertions, async tests, and coverage when tests are in scope.
- Use `httpx.MockTransport` for unit tests of outbound clients.
- Use `httpx.ASGITransport` for in-process tests against ASGI apps when appropriate.
- Do not call real external APIs in unit tests.
- Do not use real sleeps in retry, backoff, or rate-limit tests; inject sleep/clock/randomness when project code owns the waiting behavior, or use documented `httpx-retries` hooks/fixtures where available.
- Test success parsing, timeout and network errors, non-2xx mapping, invalid JSON/schema, retry boundaries, auth/header construction, SSRF rejection, and streaming close behavior.
- Test named-client configuration conflicts: requesting the same client name with different timeout, base URL, auth, limits, SSL, proxy, retry, rate-limit, or `trust_env` policy must fail or use a distinct profile.
- Test `trust_env` behavior when proxy or SSL environment variables could affect the client.
- Test `httpx-retries` configuration when it is used: retryable methods, retryable status codes, `Retry-After`, max attempts, max backoff, jitter, total timeout, and final failure mapping.
- Test `429` handling with delay-seconds `Retry-After`, HTTP-date `Retry-After`, missing `Retry-After`, malformed `Retry-After`, and final `429` after retries are exhausted.
- Test redirect rejection or redirect target re-validation for user-influenced URLs.
- Test that shared clients are closed during application shutdown/lifespan cleanup.

## Caching

- For cached external reads, follow the active cache policy declared by `CODEX_PROJECT.md`; use active cache and framework skills for cache mechanics.
- Do not duplicate cache policy inside HTTPX clients; cache only deterministic, idempotent reads where bounded staleness is acceptable.
