# Python Service E2E Patterns And Review

Use this reference when designing or reviewing E2E tests for Python services and applications without browser UI.

## What Counts As E2E Here

A Python service E2E test should exercise the application through a public boundary and include the real composition root or a production-like test composition.

Examples:

- send an HTTP request to a configured API boundary and verify response plus durable state;
- run a CLI command and verify exit code, stdout/stderr, and filesystem/database effects;
- publish a queue message and verify the externally visible side effect;
- run a scheduled job command or entrypoint with real test dependencies and verify output state;
- process input files through the public command or application entrypoint and verify output artifacts.

## Good: CLI Through Process Boundary

```python
import os
import subprocess
import sys
from pathlib import Path


def test_exports_report_file(tmp_path: Path) -> None:
    output_dir = tmp_path / "report-output"
    env = {
        **os.environ,
        "APP_ENV": "test",
    }

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "app.cli",
            "export-report",
            "--out",
            str(output_dir),
        ],
        env=env,
        text=True,
        capture_output=True,
        timeout=30,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    report_path = output_dir / "report.json"
    assert report_path.exists()
    assert '"summary"' in report_path.read_text(encoding="utf-8")
```

Why this is good:

- The test uses the same command boundary as users or automation.
- It verifies externally visible process and filesystem behavior.
- Temporary files are isolated through `tmp_path`.
- Subprocess execution has a timeout and captures diagnostics.

## Bad: E2E That Calls Internals Directly

```python
from app.reports.service import export_report


def test_exports_report() -> None:
    result = export_report()

    assert result is not None
```

Problems:

- This is closer to a unit or integration test.
- It bypasses CLI parsing, config loading, process behavior, serialization, and real composition.
- The assertion is too weak to prove user-visible behavior.

## Good: Real Disposable Dependency

Use this pattern only when Testcontainers is already declared by the project or explicitly approved.

```python
import os

from testcontainers.postgres import PostgresContainer


def test_creates_invoice_through_real_database() -> None:
    with PostgresContainer("postgres:16", driver=None) as postgres:
        os.environ["DATABASE_URL"] = postgres.get_connection_url()
        run_migrations(os.environ["DATABASE_URL"])

        result = run_app_command("create-invoice", "--customer", "cust-e2e-001")

        assert result.returncode == 0
        assert invoice_exists("cust-e2e-001")
```

Why this is good:

- The database behavior is real.
- The dependency is disposable.
- Setup and teardown are explicit.
- The scenario verifies behavior through an application command, not through repository internals.

## Bad: Shared Uncontrolled Database

```python
os.environ["DATABASE_URL"] = "postgresql://shared-dev-db/app"
```

Problems:

- Tests can destroy or depend on shared state.
- Failures may depend on another developer, CI job, or manual data changes.
- Cleanup is hard to guarantee.
- The test may accidentally hit unsafe infrastructure.

## Good: Filesystem Flow With Isolated Data

```python
import subprocess
import sys
from pathlib import Path


def test_imports_orders_file(tmp_path: Path) -> None:
    input_file = tmp_path / "orders.csv"
    output_file = tmp_path / "result.json"
    input_file.write_text("order_id,amount\nord-e2e-001,10.50\n", encoding="utf-8")

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "app.cli",
            "import-orders",
            "--input",
            str(input_file),
            "--output",
            str(output_file),
        ],
        text=True,
        capture_output=True,
        timeout=30,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert output_file.exists()
    assert "ord-e2e-001" in output_file.read_text(encoding="utf-8")
```

Why this is good:

- The test uses a public process boundary.
- Input and output files are isolated.
- The assertion targets a stable artifact.

## Bad: Fixed Sleep For Async Completion

```python
queue.publish({"type": "send-email", "id": "msg-123"})
time.sleep(5)
assert sent_emails.count() == 1
```

Problems:

- The test can be slow and flaky.
- It may pass or fail based on machine timing.
- It hides the real readiness condition.

## Good: Bounded Wait For Observable Result

```python
import time
from collections.abc import Callable


def eventually(assertion: Callable[[], None], *, timeout: float = 5.0, interval: float = 0.1) -> None:
    deadline = time.monotonic() + timeout
    last_error: AssertionError | None = None

    while time.monotonic() < deadline:
        try:
            assertion()
            return
        except AssertionError as exc:
            last_error = exc
            time.sleep(interval)

    if last_error is not None:
        raise last_error


def assert_sent_email_exists(sent_emails, message_id: str) -> None:
    assert sent_emails.count_by_message_id(message_id) == 1


def test_worker_sends_email(queue, sent_emails) -> None:
    queue.publish({"type": "send-email", "id": "msg-123"})

    eventually(lambda: assert_sent_email_exists(sent_emails, "msg-123"))
```

Why this is good:

- The wait condition is explicit.
- The test can finish quickly when the system is ready.
- Timeout failures point to the missing observable result.

## Dependency Pattern

- Use real disposable dependencies for core behavior: database, Redis/cache, queue, object storage, broker, local mail/SMS fake, or provider sandbox.
- Use Testcontainers when containers are allowed and the dependency is important to the flow.
- Use project-declared Docker Compose when the repository already standardizes service dependencies that way.
- Stub third-party providers when the provider is outside the E2E scope, paid, unstable, unavailable in CI, or unsafe for automated tests.
- Prefer a local fake server or contract-faithful fake over patching internals.

## Data Pattern

- Run migrations before tests when the flow depends on schema.
- Seed only the minimum required records.
- Use unique test IDs or isolated databases, schemas, queues, cache namespaces, buckets, temp directories, and ports.
- Clean data after tests or use disposable environments.
- Keep fixtures readable and close to the scenario.

## Anti-patterns

- Mocking the whole service composition root.
- Importing private modules and calling internal functions directly.
- Sharing one mutable database state across unrelated tests.
- Sleeping for arbitrary time instead of waiting for readiness or observable completion.
- Running against production-like shared environments without explicit safety controls.
- Duplicating unit tests as slow E2E tests.
- Adding Docker/Testcontainers/HTTP mocking tools without project approval.
- Treating E2E coverage as a replacement for business logic unit/integration tests.

## Review Questions

- What public boundary is under test?
- Which dependencies are real and why?
- Which dependencies are stubbed and why?
- How are migrations, seed data, and cleanup handled?
- Can the test run independently and in any order?
- Can it run in CI without hidden local state?
- Can it accidentally hit production or shared uncontrolled systems?
- Does it verify externally visible behavior instead of implementation details?
- Does a narrower unit or integration test already cover the same confidence?
