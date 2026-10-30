# Source Code Hygiene

Apply this rule when creating, editing, reviewing, or refactoring source code, tests, comments, docstrings, configuration constants, runtime strings, or generated developer-facing artifacts.

## Purpose

Keep product code free of planning, backlog, task-management, and implementation-history artifacts unless those values are real product-domain data.

## Rule

- Do not copy internal planning/taskbook identifiers, backlog item IDs, ticket IDs, workflow labels, DoD references, implementation-history notes, review markers, or temporary planning names into source code.
- This applies to production code, tests, comments, docstrings, test names, constants, configuration defaults, error messages, log messages, API payload values, seed data, fixtures, snapshots, migrations, and runtime strings.
- Allowed exceptions are values that are part of the real product contract, public API contract, persisted domain data, external integration contract, or repository-required traceability metadata.
- When a planning concept must be represented in code, rewrite it into a product-level name that describes behavior or domain meaning instead of the planning artifact.
- Do not add tests that assert the absence of deleted planning artifacts unless absence itself is a real product requirement.
- Do not preserve temporary names or workaround labels only for implementation-history reasons.

## Review Checklist

- [ ] No task, backlog, DoD, ticket, workflow, or implementation-history marker leaked into source code or tests.
- [ ] Test names describe product behavior, not task-management history.
- [ ] Runtime strings and constants contain product-domain names, not planning artifacts.
- [ ] Any remaining planning-like token is justified as real product-domain data or external contract data.
