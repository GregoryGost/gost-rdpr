# Python service E2E testing rules

Apply this rule when `CODEX_PROJECT.md` declares Python service E2E testing active, or when the task directly changes E2E tests for a non-browser Python application.

This rule is for Python services, APIs, CLIs, workers, queue consumers, scheduled jobs, database-backed flows, and filesystem flows. Do not use Playwright, Selenium, browser automation, DOM assertions, or UI validation tools here.

## Required skills

Use together with:

- `python-core`;
- `python-testing`;
- `python-service-e2e-testing`.

Add specialist skills only when they are active in `CODEX_PROJECT.md` or directly touched by the task:

- `python-fastapi-expert` for FastAPI/API boundaries;
- `python-cashews-cache` for `cashews` cache-backed flows;
- `python-nats-kv-cache` for NATS JetStream KV cache-backed flows;
- database-specific rules/skills for persistence behavior;
- HTTP-client or external-system rules for integrations outside the application boundary.

## Source of truth

Before adding or changing Python service E2E tests:

1. Read `CODEX_PROJECT.md`.
2. Check application type: HTTP API, CLI, worker, queue consumer, scheduled job, filesystem flow, database-backed flow, or mixed service.
3. Check declared E2E command, pytest command, dependency policy, environment policy, data isolation policy, container policy, coverage policy, and artifact policy.
4. Inspect `pyproject.toml`, lock files, pytest configuration, app entrypoints, composition root, config loader, migrations, seeds, env loading, and existing E2E tests.
5. Identify the public boundary under test and keep assertions at that boundary.
6. Load `python-service-e2e-testing/references/patterns-and-review.md` when adding or changing service E2E tests.
7. Use project-declared commands and do not invent script names.
8. Do not add Testcontainers, Docker Compose, pytest-httpserver, RESPX, pytest-xdist, tox, nox, or other tools unless the project already declares them or the user explicitly approves them.

## Relationship to existing rules

- `python-core` defines Python language, typing, resource ownership, exceptions, and Python-code review.
- `python-testing` defines pytest-based unit and integration testing, fixtures, async tests, mocks, xdist, and coverage.
- This rule adds service-level E2E behavior across real process, application, network, dependency, filesystem, queue, or persistence boundaries.
- Do not duplicate unit or integration tests here when a narrower test gives the same confidence.
- Do not use E2E tests only to raise coverage percentage; coverage still needs meaningful unit and integration coverage for business logic.

## E2E boundaries

Use the real public boundary of the application:

- HTTP API: call the running service over HTTP, or use an explicitly declared in-process app boundary when the project accepts it.
- CLI: run the installed or project-declared command through a subprocess boundary.
- Worker or queue consumer: publish a message/job and observe public side effects.
- Scheduled job: run the public job entrypoint or project-declared command and verify durable effects.
- Database-backed flow: run migrations/seeds and verify externally visible behavior through the application boundary.
- Filesystem flow: use isolated temp directories and verify input/output artifacts.
- Mixed flow: keep the scenario small and name the primary boundary being validated.

## Dependencies and data

- Prefer disposable real dependencies for E2E: test database, Redis/cache, broker, object storage, local provider fake, or other service dependencies.
- Use Testcontainers for focused disposable dependencies when the project policy allows containers.
- Use project-declared Docker Compose services when the repository standardizes multi-service test dependencies that way.
- Run migrations and seed only the data required for the scenario.
- Isolate E2E data by unique IDs, schemas, databases, queues, buckets, cache namespaces, temp directories, ports, or cleanup hooks.
- Never run destructive E2E tests against production or shared uncontrolled environments.

## Mocking policy

- Do not mock the application module under test.
- Do not replace the main composition root with isolated unit-test wiring.
- Do not mock services, use cases, validators, repositories, or business branches inside the E2E scope.
- Stub only dependencies outside the E2E scope, such as paid third-party APIs, unstable external systems, unavailable provider sandboxes, or systems that are unsafe to call from CI.
- Prefer contract-faithful local fakes or local HTTP servers for external systems when real dependencies are impractical.
- Keep mocks explicit and local to the E2E scenario.

## pytest E2E policy

- Use pytest as the runner/orchestrator unless the project already requires another runner.
- Keep E2E file patterns, markers, timeout policy, setup, teardown, and environment explicit.
- Register an `e2e` marker when E2E tests are separated from unit and integration tests.
- Keep E2E commands separate from unit/integration commands when setup cost or runtime is meaningful.
- Keep type checking as a separate validation step unless the project explicitly performs it through the test command.
- Run E2E tests serially by default.
- Use `pytest-xdist` only when E2E resources are isolated per worker and the project declares xdist active.

## Determinism and cleanup

- Avoid fixed sleeps. Prefer readiness checks, health endpoints, wait strategies, explicit event completion, observable state, or bounded polling.
- Use timeouts for subprocesses, HTTP calls, async jobs, queue waits, container startup, and polling loops.
- Control clocks, random IDs, UUIDs, ports, environment variables, files, queues, cache namespaces, and external calls when they affect observable behavior.
- Ensure app instances, containers, database connections, files, queues, cache keys, child processes, environment variables, and ports are cleaned up after tests.
- Capture stdout, stderr, logs, and generated artifacts needed to diagnose failures.
- Report known setup gaps, unavailable dependencies, or non-reproducible environment assumptions.

## Review checklist

- [ ] The target is non-browser Python, not browser/UI E2E.
- [ ] The public boundary under test is explicit.
- [ ] The scenario validates a critical user/system flow, not an internal branch.
- [ ] The application under test is not mocked.
- [ ] Real/containerized/stubbed dependencies are justified.
- [ ] Migrations, seed data, and cleanup are deterministic and isolated.
- [ ] The test cannot hit production or shared uncontrolled systems.
- [ ] Setup and teardown clean up app instances, containers, connections, env, ports, queues, cache keys, child processes, and temp files.
- [ ] Assertions target externally visible behavior.
- [ ] E2E command comes from project configuration.
- [ ] Unit/integration coverage was not duplicated unnecessarily.
