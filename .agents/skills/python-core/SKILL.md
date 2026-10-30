---
name: python-core
description: "Use for Python 3.14+ implementation, refactoring, typing, PEP-oriented style, validation workflow, and code review."
---
# Python Core

## Overview

Use this skill for Python-language coding and review work when `CODEX_PROJECT.md` declares Python as an active programming language, or when the task explicitly asks to inspect Python files.

This skill covers Python-level rules only: syntax, style, typing, resource ownership, exceptions, comments/docstrings, validation, and language-level review. It does not define framework, database, HTTP client, cache, web API, or security policy. Combine it with active specialist skills when the task touches those areas.

For concrete examples, anti-patterns, and review checklist items, load `references/patterns-and-review.md` when reviewing Python code quality or refactoring Python files.

## Scope And Coordination

- Read `CODEX_PROJECT.md` and repository metadata before changing Python behavior.
- Follow repository configuration over generic preferences: formatter, linter, type checker, dependency manager, virtual environment, and test runner.
- Do not assume `poetry`, `uv`, `pip`, `pytest`, `ruff`, `mypy`, `pyright`, or another tool when repository metadata declares something else.
- Apply this skill before Python implementation changes and then add relevant active specialist skills for tests, framework code, persistence, HTTP clients, security, caching, CLI, packaging, or other stack-specific behavior.
- Do not copy framework/database/HTTP/security rules into this skill. Route to active specialist skills declared by `CODEX_PROJECT.md` instead.

## PEP-Oriented Style Defaults

- Use PEP 8 as the default style baseline when the repository has no stronger configuration.
- Prefer 4 spaces per indentation level in portable examples and new Python projects. Use a different indentation style only when `CODEX_PROJECT.md`, repository formatter configuration, or existing local code explicitly requires it.
- Keep imports at the top of the file after module comments/docstrings and before module globals/constants.
- Group imports as standard library, third-party, then local imports, separated by one blank line. Sort within groups when this matches repository tooling.
- Prefer absolute imports for clarity. Use explicit relative imports only when they fit the package layout better.
- Use two blank lines before top-level definitions and one blank line between methods inside classes unless repository tooling enforces another convention.
- Follow repository line-length tooling. If no tool is configured, prefer PEP 8's conservative defaults: 79 characters for code and 72 for comments/docstrings, or up to 99 characters only when the team/project explicitly accepts it.
- Prefer implicit line continuation inside parentheses, brackets, and braces over backslash continuations.
- Use `snake_case` for functions and variables, `PascalCase`/CapWords for classes, and `UPPER_CASE` for constants unless an external API or existing project convention requires otherwise.
- Avoid visually ambiguous one-character names such as `l`, `O`, and `I`.

## Python Version And Compatibility

- Use the Python version declared by `CODEX_PROJECT.md` and repository metadata. Never introduce Python 2 syntax or patterns.
- For Python 3.14+ projects, prefer modern built-in generic types such as `list[str]`, `dict[str, int]`, `set[str]`, and `tuple[str, ...]`.
- Prefer `X | None` and `A | B` union syntax when the active Python version supports it and repository style agrees.
- Use `type AliasName = ...` for new type aliases when the active Python version is Python 3.12+ and type-checker/tooling support is adequate.
- Prefer `collections.abc` protocols such as `Iterable`, `Iterator`, `Sequence`, `Mapping`, `MutableMapping`, and `Callable` for input abstractions when concrete containers are not required.
- Do not use deprecated `typing.ByteString` or `collections.abc.ByteString` in Python 3.14+ code. Use `collections.abc.Buffer` for runtime buffer checks, or explicit annotations such as `bytes | bytearray | memoryview` when those are the supported inputs.
- Do not rely on private typing implementation details. Use documented helpers such as `typing.get_origin()` and `typing.get_args()` for type introspection.
- Python 3.14 uses deferred evaluation of annotations. If code introspects annotations at runtime, use documented APIs such as `annotationlib.get_annotations()` or `typing.get_type_hints()` according to the needed format and compatibility requirements; do not depend on raw `__annotations__` implementation details.
- Do not add `from __future__ import annotations` mechanically in Python 3.14+ code. Preserve it in existing modules when required for cross-version behavior, but do not introduce it without a concrete compatibility reason.
- Use f-strings for ordinary string interpolation. Use Python 3.14 template string literals (`t"..."` / `t'...'`) only when code intentionally needs a `string.templatelib.Template` object for custom processing; do not use them as an f-string replacement.
- Avoid `return`, `break`, or `continue` that exits a `finally` block. In Python 3.14 this pattern emits `SyntaxWarning` and can suppress active exceptions.

## Environment And Dependency Discovery

- Detect dependency tooling from repository metadata before adding or changing dependencies: `pyproject.toml`, lock files, README instructions, CI, and existing scripts.
- Use the project virtual environment only when `CODEX_PROJECT.md` or repository setup declares it.
- Do not add or replace runtime, development, testing, security, retry, database, cache, or formatting dependencies without explicit user approval.
- If repository metadata and `CODEX_PROJECT.md` disagree, report the conflict before changing dependency behavior.
- Prefer the standard library for straightforward functionality when it is readable and maintainable. Do not add dependencies to avoid a small amount of clear project-local code.

## Validation Workflow

- Run the smallest useful validation first, then broaden when the change touches multiple areas.
- Prefer module execution for Python tools, for example `python -m pytest` or `python -m compileall`, unless repository scripts define another command.
- Syntax-check changed Python files with `py_compile` or the project with `compileall` when relevant.
- Do not mask test failures with fallback commands.
- If checks cannot be run, state what was not run and why.

## Pythonic Implementation Rules

- Prefer clear, boring code over cleverness. Use modern Python features only when they improve readability and maintainability.
- Prefer small pure functions for business rules when this improves testability.
- Prefer `pathlib` over `os.path` for new path code unless existing project conventions use another approach.
- Use context managers for files, locks, temporary resources, network resources, and other lifecycle-bound objects.
- Use f-strings for ordinary formatting.
- Use type hints on public functions and methods that are part of a stable project contract.
- Use dataclasses for simple data containers when validation, inheritance, or framework-specific models are not required. Consider `frozen=True` when values should be immutable.
- Use `Enum` or `StrEnum` for closed symbolic sets when plain strings would make invalid states easy to create.
- Use `is None` and `is not None` for `None` checks.
- Use `isinstance()` for runtime type checks instead of comparing `type(obj)` directly, unless exact type identity is intentionally required and documented.
- Prefer truthiness checks such as `if not items:` for standard containers when emptiness is the intended condition.
- Avoid mutable default arguments, bare `except`, wildcard imports, hidden global mutable state, string concatenation in loops, and compound statements that pack multiple actions into one line.
- Do not catch broad exceptions unless the boundary requires it and the handling is explicit, logged safely, and tested.
- Use exception chaining (`raise NewError(...) from exc`) when translating low-level exceptions into higher-level errors.
- Avoid control flow in `finally` blocks that suppresses exceptions.

## Comments And Docstrings

- Follow the natural-language policy declared in `CODEX_PROJECT.md` for comments, docstrings, test comments, and documentation.
- Use triple double quotes for docstrings.
- Put docstrings immediately after the module, class, function, or method definition.
- Public modules, exported functions/classes, and public methods should have docstrings when they are part of a stable project contract.
- One-line docstrings should be concise summaries. Multi-line docstrings should start with a summary line, then a blank line, then details.
- Function/method docstrings should document arguments, return values, side effects, raised exceptions, restrictions, and keyword-argument semantics when these are part of the public contract.
- Comments should explain non-obvious business rules, invariants, trade-offs, side effects, and safety constraints. Do not add comments that merely restate obvious code.

## Review Workflow

When reviewing Python code:

1. Inspect changed production files, nearby tests, project metadata, settings, and existing patterns before proposing changes.
2. Identify touched areas: Python language/core, tests, framework/API, service layer, persistence, HTTP client, cache, security, configuration, tooling, packaging, or CLI.
3. Apply this skill together with every relevant active specialist skill declared by `CODEX_PROJECT.md`.
4. Review code and tests together. Do not approve a functional change when important success, failure, boundary, integration, or regression behavior is untested.
5. Check that new code follows existing project architecture instead of introducing parallel patterns.
6. Check that errors are mapped at the correct boundary and do not leak internal implementation details.
7. Check that resources have explicit lifecycle ownership: files, temporary directories, locks, subprocesses, async tasks, network clients, database sessions when present, streams, and fixtures.
8. Check that tests do not introduce real network calls, real sleeps, hidden global state, hardcoded secrets, or environment-specific assumptions.
9. Run or request validation commands declared by `CODEX_PROJECT.md` and repository metadata.
10. Report what was checked, what could not be checked, and why.
