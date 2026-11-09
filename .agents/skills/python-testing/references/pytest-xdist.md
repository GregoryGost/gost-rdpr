# pytest-xdist Patterns And Review

Use this reference when `pytest-xdist` is declared in project dependencies or when `CODEX_PROJECT.md` explicitly declares parallel pytest execution active.

Do not add `pytest-xdist` to a project without explicit user approval.

## Activation

Use xdist for broad validation only after the relevant focused serial tests pass.

Good default commands:

```bash
python -m pytest -n auto
python -m pytest -n auto --dist loadscope
python -m pytest -n auto --dist loadfile
python -m pytest -n 0
```

Use `-n 0` to disable xdist and rerun failures in the main process.

## Distribution Modes

- Use `--dist load` for ordinary independent tests.
- Use `--dist loadscope` when module-level or class-level fixtures should stay together.
- Use `--dist loadfile` when tests in the same file share expensive or coupled setup.
- Use `--dist loadgroup` only when the project already uses `xdist_group` markers.
- Use `--dist worksteal` only when uneven test durations make default load scheduling inefficient.

## Safety Rules

Tests must be parallel-safe before `-n auto` becomes a normal validation command.

Check for:

- shared SQLite files or database names;
- shared process/global mutable state;
- fixed network ports;
- fixed temporary paths;
- shared cache keys or external resources;
- tests depending on execution order;
- parametrization built from unordered sets, dicts, or generators;
- fixtures with hidden cross-test state.

Use `tmp_path`, worker-specific resource names, isolated databases, isolated cache namespaces, and explicit cleanup when tests run with xdist.

## Bad: Shared SQLite File Across Workers

```python
async def test_repository(shared_sqlite_path: Path) -> None:
    repository = Repository.from_path(shared_sqlite_path)

    await repository.create_item("a")

    assert await repository.count_items() == 1
```

Problem: multiple workers can write to the same file and make the test flaky.

## Good: Worker-Scoped SQLite Path

```python
async def test_repository(tmp_path: Path, worker_id: str) -> None:
    database_path = tmp_path / f"test-{worker_id}.sqlite3"
    repository = Repository.from_path(database_path)

    await repository.create_item("a")

    assert await repository.count_items() == 1
```

Why this is good:

- The resource name includes the xdist worker id.
- The database lives under `tmp_path`.
- Workers do not share the same SQLite file.

## Bad: Unordered Parametrization

```python
import pytest


@pytest.mark.parametrize("value", {"a", "b", "c"})
def test_value(value: str) -> None:
    assert value
```

Problem: xdist requires workers to collect the same tests in the same order.

## Good: Deterministic Parametrization

```python
import pytest


@pytest.mark.parametrize("value", ["a", "b", "c"])
def test_value(value: str) -> None:
    assert value
```

## Debugging

Do not debug distributed tests with `-s`, `--capture=no`, or `--pdb`.

When a parallel run fails:

1. Rerun the failing test with `python -m pytest -n 0 path/to/test.py::test_name`.
2. If it passes serially, inspect shared resources, hidden global state, and fixture scopes.
3. Keep the fix deterministic before re-enabling `-n auto`.

## Review Checklist

- [ ] `pytest-xdist` is declared in project dependencies or `CODEX_PROJECT.md`.
- [ ] Focused serial tests pass before broad xdist validation.
- [ ] Tests do not depend on execution order.
- [ ] Parametrization order is deterministic.
- [ ] Databases, caches, files, ports, and external resources are isolated per worker.
- [ ] Module/class fixture coupling uses `--dist loadscope` or `--dist loadfile` when needed.
- [ ] Failures are rerun with `-n 0` before debugging.

## Official Sources

- pytest-xdist docs: https://pytest-xdist.readthedocs.io/en/stable/
- Running tests across multiple CPUs: https://pytest-xdist.readthedocs.io/en/stable/distribution.html
- Known limitations: https://pytest-xdist.readthedocs.io/en/stable/known-limitations.html
