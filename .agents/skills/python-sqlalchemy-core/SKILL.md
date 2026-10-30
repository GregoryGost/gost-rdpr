---
name: python-sqlalchemy-core
description: "Use for backend-agnostic SQLAlchemy models, sessions, repositories, transactions, queries, error mapping, and tests."
---

# Python SQLAlchemy Core

Apply this skill for SQLAlchemy code that is not specific to one database backend.

## Required Dependencies

- `python-core`

## Optional Coordination

Apply additional active skills only when the task touches their area:

- `python-testing` for pytest, pytest-asyncio, fixtures, mocks/fakes, coverage, and integration-test review.
- `python-fastapi-expert` when SQLAlchemy code is used by FastAPI routes, dependencies, services, or OpenAPI-facing models.
- `python-backend-security` when SQL construction, authorization predicates, tenant isolation, secrets, logging, or user-controlled input are involved.
- The active database-specific skill from `CODEX_PROJECT.md` for drivers, pooling, migrations, locking, isolation, backend-specific SQL, and integration-test setup.

Read the database profile declared in `CODEX_PROJECT.md` for active database, driver, pooling layer, migration tool, runtime write policy, dependency versions, and source of truth before changing persistence behavior.

Follow the migration policy declared in `CODEX_PROJECT.md`. Do not introduce or replace migration tooling without explicit user approval.

For concrete bad/good examples and a compact review checklist, load `references/patterns-and-review.md` when implementing or reviewing SQLAlchemy models, repositories, session lifecycle, transaction boundaries, query behavior, or DB tests.

## Scope And Activation

Use this skill when creating, changing, or reviewing:

- SQLAlchemy models and mappings;
- engine and session factory wiring;
- `Session` or `AsyncSession` lifecycle;
- repository methods;
- transaction boundaries;
- raw SQL through `text()`;
- query correctness and performance;
- constraint and `IntegrityError` behavior;
- DB integration tests;
- migration-policy coordination.

Do not use this skill alone for backend-specific decisions. Apply the active database-specific skill when the task depends on driver behavior, pooling behavior, isolation behavior, migration syntax, lock behavior, or database-specific SQL.

## Repository-First Database Access

- Keep SQLAlchemy expressions, raw SQL, relationship loading, joins, filters, ordering, pagination SQL, and persistence details inside repositories.
- Treat repository public methods as complete persistence boundaries. SQLAlchemy and driver exceptions must not escape repository APIs.
- Translate expected persistence failures to stable repository/domain errors inside repository methods. Do not translate database exceptions directly to HTTP/API errors.
- Repository write methods must call `flush()` before returning whenever generated identifiers, database defaults, constraint outcomes, or error mapping depend on database execution.
- Services and routers must not import or catch `IntegrityError`, `DBAPIError`, `SQLAlchemyError`, or driver-specific exceptions.
- Keep routers free of SQLAlchemy code.
- Keep services free of accumulated ad-hoc SQL; services may choose repositories, transaction scope, and domain decisions.
- Repository methods must be explicit about whether they read, write, flush, or require a caller-owned transaction.
- Do not return live ORM entities directly to API responses. Convert to DTO/Pydantic/read models before crossing the API boundary.
- Avoid hidden lazy loading after session closure. Eagerly load required relationships or build response DTOs while the session is still valid.
- Do not cache live ORM entities or objects bound to an active session.

## Engine And Session Lifecycle

- Configure each SQLAlchemy engine once at application startup or database component initialization, not per request, route, service, or repository call.
- Configure session factories once next to engine wiring.
- Use one `Session` or `AsyncSession` per unit of work, request, task, or explicit batch.
- Keep session lifetime short and visible.
- Never share `Session` or `AsyncSession` across concurrent tasks.
- Use context managers for sessions and transactions: `with Session(...)`, `async with AsyncSession(...)`, `session.begin()`, or `async with session.begin()`.
- Do not keep long-lived sessions in services, repositories, singletons, or global state.
- Do not call synchronous SQLAlchemy code directly from an asyncio event loop unless the project has an explicit threadpool boundary.
- Keep engine disposal and shutdown behavior owned by application lifecycle or the database component lifecycle.

## Transactions And Unit Of Work

- Put read-modify-write operations inside one transaction.
- Keep transaction ownership explicit. Service/unit-of-work code should own multi-repository commits.
- Low-level repositories must not commit unless they explicitly own the whole unit of work.
- Repository write methods must use `flush()` when generated ids, constraint checks, database defaults, or typed error mapping are needed before returning to the caller.
- Use database constraints for correctness under concurrency. Pre-checks improve error messages but are not correctness boundaries.
- Repository methods must catch expected SQLAlchemy/database exceptions raised by their own execute/flush operations and translate them to stable repository/domain errors with exception chaining.
- A caller-owned transaction still controls commit and rollback; repository error mapping must not hide or commit the transaction.
- Do not perform external HTTP calls, slow computations, sleeps, cache calls, filesystem scans, or network operations while holding a write transaction.
- Perform cache invalidation or external side effects only after a successful commit.
- If the transaction rolls back, cache state and external side effects must remain unchanged unless a project-specific compensation flow exists.

## Query Correctness And Performance

- Use SQLAlchemy expressions or parameterized `text()` queries. Never interpolate user input with f-strings, `.format()`, `%`, or string concatenation.
- Treat dynamic `ORDER BY`, column names, table names, and sort direction as unsafe unless mapped through allowlists.
- Define stable ordering before applying `limit`/`offset`, cursor pagination, or batch windows.
- Use explicit indexes for lookup, join, filtering, ordering, and uniqueness paths that matter to behavior or latency.
- Use uniqueness constraints and check constraints for invariants instead of relying only on service-level checks.
- Avoid N+1 queries. Use explicit eager loading, aggregate queries, projection queries, or repository methods that return pre-shaped read models.
- Use pagination for list endpoints and repository list methods.
- Avoid returning unbounded result sets from repositories used by API handlers.
- Keep backend-specific query-plan inspection in the active database-specific skill.

## Error Mapping

- The repository layer is the persistence error-mapping boundary.
- Catch expected `IntegrityError`, `DBAPIError`, and other known SQLAlchemy/database exceptions inside repository methods around the execute/flush operation that can raise them.
- Translate them to stable repository/domain errors that callers can handle without importing SQLAlchemy. Preserve the original exception as the cause with `raise ... from exc`.
- Do not map persistence exceptions directly to HTTP status codes or API response models inside repositories. Service/API layers translate typed repository/domain errors to their public contracts.
- Do not expose raw SQL, constraint names, schema names, internal file paths, connection strings, or stack traces to API clients.
- Preserve enough safe context for logs: operation name, repository method, sanitized entity identifiers, and stable domain error code where applicable.
- Do not catch broad database exceptions only to return generic success, silently skip failed writes, or erase actionable failure categories.

## Models And Schemas

- Keep SQLAlchemy database models separate from FastAPI/Pydantic request and response models.
- Keep internal domain objects or DTOs separate from persistence models when business rules would otherwise leak persistence details.
- Do not expose ORM relationship names or implementation-only fields through public API schemas.
- Use clear naming for database models, API schemas, repositories, and DTO/read models according to existing project conventions.

## Migration Policy Coordination

- Follow the migration policy declared in `CODEX_PROJECT.md`.
- Do not introduce Alembic, raw SQL migrations, migration runners, or replacement tooling unless the user explicitly approves or the repository already standardizes on it.
- Migration changes must be deterministic, reviewable, and covered by tests appropriate to the active database backend.
- Database-specific migration syntax, lock behavior, online/offline migration behavior, and rollback policy belong to the active database-specific skill.

## Testing Requirements

- Apply `python-testing` for general pytest, pytest-asyncio, fixtures, coverage, mocks/fakes, and assertion rules when tests are in scope.
- Unit tests may mock repositories when testing services or business logic, but such tests do not cover repository SQL behavior.
- Repository integration tests must use the real engine/session/connection path for the active database backend.
- Do not mock SQLAlchemy in repository integration tests.
- Test transaction commit and rollback behavior for multi-step units of work.
- Test constraint violations through repository methods and assert the typed repository/domain errors they expose.
- Verify that raw SQLAlchemy or driver exceptions do not escape repository public methods.
- Test pagination, ordering, filtering, and permission/tenant predicates when they affect behavior.
- Use the active database-specific skill for backend-specific test database setup and isolation rules.

## Review Workflow

When reviewing common SQLAlchemy code:

- Load `references/patterns-and-review.md` for concrete anti-patterns and the final review checklist.
- Confirm the required `python-core` dependency; apply `python-testing` and the active database-specific skill when tests or backend-specific behavior are in scope.
- Inspect models, repositories, engine/session setup, transaction owners, settings, tests, and existing DB conventions.
- Verify that SQL/ORM details stay inside repositories and do not leak into routers or unrelated services.
- Verify that sessions are scoped to one unit of work, request, task, or explicit batch and are not shared across concurrent tasks.
- Verify that transaction boundaries are explicit and write transactions are short.
- Verify that read-modify-write operations are protected by one transaction and database constraints.
- Verify that repository write methods flush when database execution is required for generated values, constraints, or error mapping.
- Verify that repositories translate expected SQLAlchemy/database exceptions to typed repository/domain errors and that services/routers do not catch SQLAlchemy exceptions.
- Verify that query code is parameterized and does not use f-strings or string concatenation with user-controlled input.
- Verify that dynamic sorting/filtering inputs are allowlisted.
- Verify that repository integration tests use real SQLAlchemy behavior instead of mocking SQLAlchemy.
- Verify that backend-specific mechanics are delegated to the active database-specific skill.
