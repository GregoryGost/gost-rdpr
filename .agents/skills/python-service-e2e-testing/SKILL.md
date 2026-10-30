---
name: python-service-e2e-testing
description: "Use for E2E testing of non-browser Python APIs, CLIs, workers, queues, scheduled jobs, databases, and filesystem flows."
---

# Python Service E2E Testing

Use this skill for Python projects that do not expose a browser UI: APIs, CLIs, workers, queue consumers, scheduled jobs, filesystem flows, database-backed flows, or mixed services.

Apply `CODEX_PROJECT.md`, `.codex/rules/python_service_e2e_testing.md`, `python-core`, and `python-testing` together with this skill.

Add active specialist skills only when the target project declares or touches those areas, such as `python-fastapi-expert`, `python-cashews-cache`, `python-nats-kv-cache`, database-specific skills, HTTP-client skills, or external-system skills.

Load references when needed:

- `references/patterns-and-review.md` for E2E design patterns, code examples, anti-patterns, and review prompts.
- `references/official-sources.md` for official pytest, pytest-asyncio, pytest-xdist, Testcontainers, Docker Compose, subprocess, tempfile, and related references.

## Workflow

1. Read `CODEX_PROJECT.md`.
2. Confirm that the target is a non-browser Python project.
3. Identify the public E2E boundary: HTTP API, CLI command, worker, queue consumer, scheduled job, filesystem flow, database-backed flow, or mixed service.
4. Inspect `pyproject.toml`, lock files, pytest config, service entrypoint, composition root, config loader, migrations, seeds, env loading, CI, and existing E2E tests.
5. Confirm project-declared E2E command, setup, teardown, dependency policy, environment policy, data isolation policy, port policy, and artifact policy.
6. Decide which dependencies should be real, containerized, project-declared, or stubbed.
7. Add the smallest E2E scenario that validates a critical user/system flow.
8. Run or report the project-declared E2E command.

## Baseline

- Use pytest as the runner/orchestrator unless the project already requires something else.
- Use subprocess boundaries for CLI tests.
- Use real HTTP against a running service for black-box API tests when the project declares an HTTP service boundary.
- Use an in-process app boundary only when `CODEX_PROJECT.md` or existing tests explicitly accept it for Python service E2E.
- Use real message/job publication and public side effects for workers and queue consumers.
- Use isolated temp directories for filesystem flows.
- Use Testcontainers or project-declared Docker Compose for real disposable dependencies when allowed.
- Keep E2E tests separate from unit/integration tests when setup cost or runtime is meaningful.
- Do not use Playwright, Selenium, browser tools, DOM assertions, or UI validation workflows for Python service E2E.
- Do not add new testing or infrastructure dependencies without explicit user approval or an existing project declaration.

## Boundary Selection

Choose the narrowest public boundary that proves the user/system flow:

- CLI: run the same command a user or scheduler would run.
- HTTP API: send a request through the configured app/server boundary and assert response plus durable effects.
- Worker/queue: enqueue or publish through the configured producer path and observe the final effect.
- Scheduled job: invoke the public job command or scheduler entrypoint and verify durable effects.
- Filesystem pipeline: provide input files/directories and verify output artifacts.
- Database-backed flow: run migrations/seeds and verify behavior through the application boundary, not by calling repository internals.

## Dependency Policy

- Use real dependencies only when they are disposable, local, containerized, project-declared, or otherwise explicitly approved.
- Do not call real paid, production, shared uncontrolled, or user-owned external systems from automated E2E tests.
- Stub third-party providers when they are outside the E2E scope, unsafe, paid, unstable, unavailable in CI, or not controlled by the test run.
- Prefer contract-faithful fakes, local fake servers, `pytest-httpserver`, RESPX, provider sandboxes, or project-approved adapters over patching internals.
- Keep dependency setup and teardown deterministic; clean containers, app instances, queues, cache keys, temp files, ports, and environment variables.

## Guardrails

- Do not mock the application under test.
- Do not weaken Python visibility or export internals for E2E.
- Do not replace the real composition root with unit-test wiring.
- Do not run destructive tests against production or shared uncontrolled environments.
- Keep scenario data isolated and cleaned up.
- Prefer readiness checks, health probes, observable events, explicit completion signals, or bounded polling over fixed sleeps.
- Clean up app instances, containers, connections, temp files, queues, cache keys, child processes, environment variables, and ports.
- Preserve fixture, mock, async, xdist, and coverage policy from `python-testing`.
- Keep E2E scenarios small, critical, and behavior-oriented.
- Treat E2E coverage as additional confidence, not a replacement for unit/integration coverage of business logic.

## Review Checklist

- [ ] The target is non-browser Python, not browser/UI E2E.
- [ ] Public boundary under test is explicit.
- [ ] The scenario covers a critical user/system flow.
- [ ] The application under test is not mocked.
- [ ] Real/containerized/stubbed dependencies are justified.
- [ ] No real paid, production, or shared uncontrolled external system is called.
- [ ] Migrations/seeds/test data are deterministic and isolated.
- [ ] Setup and teardown clean up app instances, containers, connections, env, ports, queues, cache keys, child processes, and temp files.
- [ ] Assertions target externally visible behavior.
- [ ] E2E command comes from project configuration.
- [ ] Unit/integration coverage was not duplicated unnecessarily.
