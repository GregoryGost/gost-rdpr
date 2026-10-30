---
name: python-testing
description: "Use for Python 3.14+ tests with pytest, pytest-asyncio, optional pytest-xdist, test doubles, and coverage."
---

# Python Testing

Use pytest as the only test framework unless the project already requires something else. Prefer facts from the repository over assumptions: read `pyproject.toml`, existing tests, and relevant production files before changing test behavior or configuration.

Load references when needed:

- `references/pytest-xdist.md` when `pytest-xdist` is declared in dependencies, `CODEX_PROJECT.md` declares parallel pytest execution active, or the task touches parallel test execution.

## Baseline

- Add or update tests for every functional change.
- Tests must have comments that describe what is being tested and why when the intent is not obvious. Use the test/comment language policy declared in `CODEX_PROJECT.md`; keep class names, variable names, library names, protocol names, and other proper names in their original form.
- Test behavior and externally observable results, not private implementation details.
- Keep business logic testable separately from handlers, repositories, ORM/SQL, framework wiring, HTTP clients, workers, CLI wrappers, and serializers.
- Use `pytest`, `pytest-asyncio`, and `coverage.py` for Python 3.14+ projects.
- Use `pytest-xdist` only when it is declared in project dependencies or `CODEX_PROJECT.md`; do not add it without explicit user approval.
- Treat repository metadata and `CODEX_PROJECT.md` as the source of truth for pytest paths, file/class/function patterns, import mode, asyncio mode, loop scopes, coverage branch tracking, fail-under thresholds, and parallel-test commands.
- Do not introduce `unittest`, `src/` layout, mixed production/test files, or manual `sys.path` hacks unless the repository already requires them.
- Do not add dependencies such as `pytest-mock` or property-based testing tools without explicit user approval.
- It is necessary to check not only the test coverage to close the coverage percentage, but also the possible verification of any parameters and other functions, even if they are not yet used in other files or business logic.
- It is important to understand that a bunch of small file tests covering the logic of the same file or the same business logic is not very good and it is better to keep such tests in one file.
- You need to check the created coverage files (`.coverage`, `.coverage.*`) in the project root and delete them (even if they are not related to the current task)
- Tests should cover only existing files and business logic. There should be no checks for fallback decisions or for the fact that these fallback decisions have been deleted. If fallback decisions are prohibited, then tests should not check them. For example, if schemas, dbo/dto files have been deleted, there should be no checks for their non-existence, etc.
- Test coverage percentage doesn't mean all business logic is covered. Business logic tests and other tests should be separately reviewed and created, regardless of coverage percentage. For example, various user-facing and automation scenarios.

## Workflow

1. Identify touched production modules and classify the change: business logic, infrastructure, or integration boundary.
2. Read existing nearby tests and configuration before choosing patterns.
3. Add or update tests first when feasible, especially for bug fixes and business rules.
4. Cover success paths, failure paths, boundary values, meaningful branches, and side effects.
5. Run relevant focused tests serially before broad validation; if `pytest-xdist` is active, use it for broad validation only after focused serial tests pass.
6. Run coverage checks before finishing; report commands and results.

For bug fixes, add a regression test that fails before the fix and passes after it. Never delete, weaken, skip, xfail, or mark code `no cover` merely to make checks pass.

## Test Layout

- Keep tests in a root `tests/` directory.
- Put isolated unit tests under `tests/unit/`.
- Put integration tests under `tests/integration/`.
- Mirror production package structure when it improves navigation.
- Keep fixtures, builders, and test data out of production code.
- Name files `test_*.py` and test functions `test_<behavior>()`.

Do not assume a `src/` layout. If production packages live at the repository root, imports and configuration must reflect that.

## Repository Configuration Discovery

- Before changing test layout, marks, commands, import behavior, asyncio behavior, coverage, or parallel execution, read `CODEX_PROJECT.md` and repository test configuration first.
- For pytest, prefer `[tool.pytest.ini_options]` in `pyproject.toml` when present. Check `testpaths`, `python_files`, `python_classes`, `python_functions`, `addopts`, `markers`, `asyncio_mode`, and pytest-asyncio loop-scope settings.
- For coverage, prefer `[tool.coverage.run]` and `[tool.coverage.report]` when present. Check branch tracking, source/omit rules, excluded lines, and `fail_under` before adding or changing tests.
- Do not rewrite pytest or coverage configuration just to match examples in this skill. Examples are defaults for new or unconfigured projects only.
- When config and `CODEX_PROJECT.md` disagree, report the conflict and avoid changing test behavior until the source of truth is clear.

## pytest Configuration

Store pytest configuration in `pyproject.toml` unless the project already standardizes on another file.

```toml
[tool.pytest.ini_options]
testpaths = ["tests"]
pythonpath = ["."]
addopts = [
  "-ra",
  "--strict-config",
  "--strict-markers",
  "--import-mode=importlib",
]
markers = [
  "unit: fast isolated unit tests",
  "integration: tests requiring database, network, filesystem, framework or infrastructure boundaries",
  "slow: slow tests",
]
asyncio_mode = "auto"
asyncio_default_test_loop_scope = "function"
asyncio_default_fixture_loop_scope = "function"
```

- Use `pythonpath = ["."]` only when root-level production packages require it.
- Never add `pythonpath = ["src"]` to a non-`src` project.
- Never use `sys.path.append(...)` or `sys.path.insert(...)` inside tests.
- Register custom markers and keep `--strict-markers` enabled.
- Do not put `-n auto` into default `addopts` until the suite is proven parallel-safe and the project explicitly wants every test run to use xdist.

## pytest-xdist / Parallel Execution

Use this section only when `pytest-xdist` is declared in project dependencies or `CODEX_PROJECT.md` explicitly declares parallel pytest execution active.

- Run focused tests serially first, especially while developing or debugging failures.
- Use xdist for broad validation when the suite is parallel-safe.
- Use the project-declared xdist command and distribution mode when `CODEX_PROJECT.md` defines them; otherwise use `python -m pytest -n auto` for broad local validation.
- Use `python -m pytest -n 0` to disable xdist and rerun failures in the main process.
- Use `--dist loadscope` when module-level or class-level fixtures should stay in the same worker.
- Use `--dist loadfile` when tests in the same file share expensive or coupled setup.
- Do not use xdist for tests that share a writable SQLite file, fixed ports, fixed temp paths, global mutable state, shared cache namespaces, or external resources unless those resources are isolated per worker.
- When xdist is active, isolate SQLite files, cache namespaces, temporary paths, ports, generated test IDs, and other mutable resources per worker, or mark the affected tests to run serially according to project policy.
- Keep parametrization deterministic; avoid unordered sets, dict iteration, and generators when collected tests must be identical across workers.
- Rerun parallel failures serially before debugging or changing production code.

Load `references/pytest-xdist.md` before changing xdist configuration, adding xdist-specific tests, or reviewing parallel-test failures.

## Coverage

- Measure line and branch coverage for application code only.
- Prefer explicit production packages in `tool.coverage.run.source`.
- Never use `source = ["src"]` in a non-`src` project.
- Avoid `source = ["."]`; if unavoidable, configure `omit` for `tests`, `docs`, `scripts`, `migrations`, `build`, `dist`, and `.venv`.
- Do not include test code in coverage source.
- Do not lower `fail_under`.
- Treat coverage percentage as insufficient without meaningful assertions.
- Also the final test check should be `coverage html`. You need to check the appearance of the `htmlcov` folder and the attached report files.

Use the repository's existing threshold if present. For new Python 3.14+ projects, prefer branch coverage and at least `fail_under = 85`; target 90-95% branch coverage for critical business/domain logic.

## Unit And Integration Boundaries

Unit tests must be fast, deterministic, isolated, and independent of real network, real database, external APIs, local timezone, current time, execution order, or filesystem state outside `tmp_path`.

Use integration tests for database/repository implementations, HTTP API routing, dependency injection, framework wiring, filesystem workflows, message queues, serialization boundaries, migrations, CLI wiring, and background-worker wiring. Integration tests do not replace focused unit tests for business rules.

## Business Logic Coverage

For each meaningful business rule, cover applicable cases:

- primary and alternative successful paths;
- invalid or missing input;
- boundary values;
- permission and eligibility checks;
- allowed and forbidden state transitions;
- monetary rounding and `Decimal` behavior;
- date, time, timezone, month/year/DST boundaries;
- empty input, duplicates, ordering, partial failure, retry, idempotency, and repeated calls;
- all meaningful `if`, `match`, guard-clause, and exception branches.

Prefer extracting business rules into pure functions, domain services, validators, policies, command handlers, or use cases when code is trapped inside infrastructure.

## Assertions

- Assert exact observable outcomes: return values, state transitions, raised exception type and contract fields, persisted state, domain events, command payloads, or absence of side effects.
- Avoid weak assertions such as `is not None`, `len(items) > 0`, `.called`, or `.awaited` when a precise contract is available.
- For expected errors, assert the exception type and any stable code/message/attributes that form the contract.
- For failure paths, assert that unwanted writes, charges, publishes, sends, or mutations did not happen.

## Fixtures And Test Data

- Keep fixtures simple and explicit.
- Use local fixtures near tests unless shared broadly; keep `conftest.py` for truly shared fixtures.
- Do not hide important business preconditions inside large fixtures.
- Use small explicit test data; use builders only when they reduce noise.
- Use `tmp_path` for temporary files and `monkeypatch` for environment variables.
- Restore global/process-wide state after each test.
- When xdist is active, ensure databases, cache namespaces, ports, files, and other mutable resources are unique per worker or fully isolated.

## Async Tests

- Test async code with `pytest-asyncio` and `async def` tests.
- Do not call `asyncio.run()` inside pytest tests.
- Do not create or share event loops manually unless the repository has a documented reason.
- Keep async test and fixture loop scope at function level by default.
- Ensure background tasks finish or are cancelled cleanly inside the test.
- Put timeouts around operations that can hang.
- Release async fixture resources in `finally`.
- Test async business logic separately from async transport/framework code.

## Mocks And Test Doubles

- Mock only external boundaries: database/repository, HTTP/network client, external API, message broker, payment/email/SMS gateway, filesystem, cache, clock, UUID/random provider, scheduler, queue, object storage, or framework adapter.
- Do not mock the function, service, model, validator, policy, use case, or business branch being tested.
- Prefer a small fake or stub over a complex mock when it makes the contract clearer.
- Use `autospec=True`, `spec_set=True`, or `create_autospec` when technically possible.
- Patch where the object is used by the system under test, not where it was originally defined.
- Use `AsyncMock` and `assert_awaited*` for async dependencies; do not use plain `Mock` for awaitables.
- Do not rely only on call checks; also verify the business result or boundary payload.
- Remember that mocked code is not covered as real implementation. A unit test with a mock repository does not cover repository SQL/ORM behavior.

## Determinism

- Inject or freeze clocks; do not depend on real current time or local timezone.
- Use `zoneinfo` for timezone-aware scenarios unless the project standardizes on another library.
- Seed or inject random/UUID providers when values affect behavior.
- Avoid real sleeps; wait for events or explicit idle/shutdown hooks.
- Avoid order assertions unless order is part of the contract.
- Do not depend on machine-specific absolute paths or environment variables.
- When xdist is active, test collection order and amount must be stable across workers.

## Domain-Specific Checks

- Use exact `Decimal` assertions for money; never use `pytest.approx` for financial amounts.
- Use `pytest.approx` only for unavoidable floats.
- Cover serializers/schemas for required fields, nullable fields, unknown fields, enum values, date/time formatting, decimal formatting, and compatibility requirements.
- Cover permissions and eligibility for allowed, denied, missing user, incomplete role, owner/non-owner, disabled/suspended, and limit-boundary cases.
- Use snapshot tests only as additional protection for stable contracts; do not replace precise assertions with snapshots.
- Consider property-based tests for calculations, normalization, parsing, sorting, deduplication, state transitions, and invariants, but do not add new dependencies without approval.

## Test Review Checklist

When reviewing tests:

- Verify that tests assert observable behavior, not private implementation details.
- Reject weak assertions such as `is not None`, `len(x) > 0`, `.called`, or `.awaited` when exact outcomes, payloads, state changes, or raised errors can be asserted.
- Verify that success paths, failure paths, boundary values, meaningful branches, side effects, and regression cases are covered.
- Verify that mocks are used only at external boundaries and do not replace the business logic under test.
- Verify that async tests do not call `asyncio.run()`, do not leak background tasks, and release async resources.
- Verify that tests do not call real external APIs, depend on local timezone/current time, use real sleeps, or depend on execution order.
- Verify that integration tests cover actual repository, database, HTTP, framework, filesystem, or serialization behavior when unit tests use mocks.
- Verify that coverage changes reflect meaningful business coverage, not only line execution.
- Verify that generated coverage files such as `.coverage` and `.coverage.*` are not left in the project root.
- When xdist is active, verify worker-safe resource isolation, deterministic parametrization, and serial rerun of failures with `-n 0`.

## Commands

Prefer module execution:

```bash
python -m pytest
python -m pytest -m unit
python -m pytest -m "not integration"
python -m pytest tests/unit/path/test_file.py -q
python -m coverage run -m pytest
python -m coverage report --show-missing
```

When `pytest-xdist` is active:

```bash
python -m pytest -n auto
python -m pytest -n 0
python -m pytest -n auto --dist loadscope
python -m pytest -n auto --dist loadfile
```

Run the smallest useful test set during iteration, then broaden to full pytest and coverage when the change has wider impact. If checks cannot be run, state the reason explicitly.
