# Python Patterns And Review

Load this file when reviewing Python code quality, refactoring Python files, or checking Python anti-patterns.

Examples in this reference use PEP 8's default 4-space indentation. When editing a repository, adapt indentation, line length, formatter behavior, and natural-language comments/docstrings to `CODEX_PROJECT.md` and repository tooling.

## Pythonic Patterns

### Comprehensions

Good:

```python
squares = [number**2 for number in range(10)]
lookup = {item.id: item for item in items}
```

Use comprehensions for straightforward transformations. Prefer an explicit loop when a comprehension becomes hard to read, needs exception handling, or has meaningful side effects.

### Context Managers

Good:

```python
from pathlib import Path


def read_config(path: Path) -> str:
    """Read a UTF-8 configuration file."""
    with path.open(encoding="utf-8") as file_obj:
        return file_obj.read()
```

### Unpacking

Good:

```python
first, *rest = items
a, b = b, a
```

### EAFP Where Appropriate

Good:

```python
def get_value(data: dict[str, str], key: str, default: str) -> str:
    """Return a value from a mapping or a fallback value."""
    try:
        return data[key]
    except KeyError:
        return default
```

Use EAFP when the exceptional path is expected and the exception type is narrow. Do not use broad exception handling as normal control flow.

### f-strings

Good:

```python
message = f"User {user_id} has {count} pending tasks"
```

Use Python 3.14 template strings only when a `string.templatelib.Template` object is needed for custom string processing.

### Type Hints

Good:

```python
from collections.abc import Iterable


def count_words(items: Iterable[str]) -> dict[str, int]:
    """Build a frequency dictionary for strings."""
    result: dict[str, int] = {}
    for item in items:
        result[item] = result.get(item, 0) + 1
    return result
```

### Type Aliases

Good for Python 3.12+ projects when type-checker support is adequate:

```python
type UserId = int
type EmailLookup = dict[str, UserId]
```

### Dataclasses For Data Containers

Good:

```python
from dataclasses import dataclass


@dataclass(frozen=True)
class UserSnapshot:
    """Immutable snapshot of user data."""

    name: str
    email: str
    active: bool = True
```

### pathlib For Paths

Good:

```python
from pathlib import Path

config_path = Path.home() / ".config" / "app.json"
```

### enumerate, zip, itertools

Good:

```python
for index, item in enumerate(items):
    ...

for left, right in zip(left_items, right_items, strict=True):
    ...
```

### Exception Translation

Good:

```python
class ConfigurationError(RuntimeError):
    """Configuration file could not be read or parsed."""


def load_settings(path: Path) -> str:
    """Load settings text from a file."""
    try:
        return path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigurationError(f"Cannot read settings file: {path}") from exc
```

## Python 3.14 Compatibility Checks

- Avoid code that depends on eager annotation evaluation. Use documented annotation introspection APIs when runtime annotation inspection is required.
- Do not rely on raw `__annotations__` implementation details.
- Do not use deprecated `typing.ByteString` or `collections.abc.ByteString`; use `collections.abc.Buffer` for runtime checks or explicit supported buffer types in annotations.
- Do not introduce `return`, `break`, or `continue` that exits a `finally` block.
- Do not use private typing internals such as `typing._UnionGenericAlias`; use documented helpers like `typing.get_origin()` and `typing.get_args()`.

## Anti-Patterns To Reject

### Mutable Default Arguments

Bad:

```python
def collect(item: str, items: list[str] = []) -> list[str]:
    """Bad: the list is reused across calls."""
    items.append(item)
    return items
```

Good:

```python
def collect(item: str, items: list[str] | None = None) -> list[str]:
    """Append an item to a new or provided list."""
    if items is None:
        items = []
    items.append(item)
    return items
```

### Bare except

Bad:

```python
try:
    do_work()
except:
    logger.exception("work failed")
```

Good:

```python
try:
    do_work()
except Exception:
    logger.exception("work failed")
    raise
```

### Broad Exception Handling Without Translation

Bad:

```python
def parse_config(raw: str) -> dict[str, str]:
    """Bad: hides the real failure and returns misleading data."""
    try:
        return parse_raw_config(raw)
    except Exception:
        return {}
```

Good:

```python
class ConfigParseError(ValueError):
    """Configuration text is invalid."""


def parse_config(raw: str) -> dict[str, str]:
    """Parse configuration text or raise a stable public error."""
    try:
        return parse_raw_config(raw)
    except ValueError as exc:
        raise ConfigParseError("Invalid configuration") from exc
```

### Control Flow In finally

Bad:

```python
def unsafe_finally() -> int:
    """Bad: return in finally suppresses active exceptions."""
    try:
        return risky_operation()
    finally:
        return 42
```

Good:

```python
def safe_finally() -> int:
    """Run cleanup without suppressing active exceptions."""
    try:
        return risky_operation()
    finally:
        cleanup()
```

### Direct Type Equality Checks

Bad:

```python
if type(value) is str:
    ...
```

Good:

```python
if isinstance(value, str):
    ...
```

### Other Anti-Patterns

- Global mutable state without explicit lifecycle ownership.
- `from module import *` in application/library code.
- String concatenation in loops instead of `"".join(parts)`.
- `== None` or `!= None` instead of `is None` or `is not None`.
- `len(value) == 0` instead of `not value` when the object has standard truthiness semantics.
- Comparing booleans to `True` or `False` with `==`.
- Compound statements that hide multiple actions on one line.
- Catching broad exceptions and silently continuing.
- Adding dependencies to avoid a small amount of straightforward project-local code without user approval.

## Review Checklist

- [ ] Python is active in `CODEX_PROJECT.md` or the task explicitly asks about Python files.
- [ ] Code follows repository formatter/linter/type-checker configuration.
- [ ] PEP 8 defaults are used when the repository has no stronger style configuration.
- [ ] Portable examples or new modules use 4-space indentation unless project configuration explicitly overrides it.
- [ ] Imports are grouped as standard library, third-party, then local imports.
- [ ] Public functions and methods have useful type hints when they form a stable project contract.
- [ ] Type annotations avoid deprecated/private typing APIs and are compatible with the active Python version.
- [ ] Runtime annotation introspection uses documented APIs.
- [ ] Comments and docstrings follow the natural-language policy declared in `CODEX_PROJECT.md`.
- [ ] Public docstrings follow PEP 257 structure where applicable.
- [ ] No mutable default arguments are introduced.
- [ ] No bare `except` or silent broad exception handling is introduced.
- [ ] Exceptions are translated with `raise ... from exc` when crossing abstraction boundaries.
- [ ] No control flow exits a `finally` block.
- [ ] Resource ownership is explicit and uses context managers where applicable.
- [ ] File paths use `pathlib` for new code unless repository convention says otherwise.
- [ ] No hardcoded secrets, tokens, credentials, or environment-specific paths are introduced.
- [ ] The smallest relevant validation command was run or the reason for not running it was reported.
- [ ] Task-specific specialist skills were applied only for active stack areas outside Python core.
