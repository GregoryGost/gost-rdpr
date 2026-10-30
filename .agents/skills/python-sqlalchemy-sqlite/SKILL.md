---
name: python-sqlalchemy-sqlite
description: "Use for SQLAlchemy with SQLite, including repositories, transactions, PRAGMAs, locking, writer queues, migrations, and tests."
---

# Python SQLAlchemy SQLite

## 1. Scope And Activation

Use this skill for SQLite-specific SQLAlchemy engines, database configuration, SQLite migrations, SQLite locking behavior, single-writer queue writes, and SQLite integration tests. Apply `python-sqlalchemy-core` together with this skill for common SQLAlchemy models, sessions, repositories, transactions, query behavior, and generic DB integration-test rules.

Do not use this skill for generic FastAPI routing unless database behavior, transaction boundaries, repository calls, or SQL/ORM behavior are involved.

Align with `python-fastapi-expert`: keep SQL and ORM query details in repositories; services coordinate business rules, transaction boundaries, and post-commit side effects.

Follow the database, migration, and runtime write policy declared in `CODEX_PROJECT.md`. Confirm the active SQLite driver, pooling library, raw SQL migration policy, single-writer queue policy, and dependency source of truth before changing persistence behavior.

For concrete bad/good examples and a compact review checklist, read `references/patterns-and-review.md` when implementing or reviewing SQLite engines, repositories, migrations, single-writer queues, transaction boundaries, or tests.

## 2. Repository-First Database Access

- Keep SQLAlchemy expressions, raw SQL, relationship loading, joins, filters, ordering, pagination SQL, and persistence details inside repositories.
- Treat repository public methods as complete persistence boundaries. SQLAlchemy, SQLite driver, and DBAPI exceptions must not escape repository APIs.
- Repository write methods must call `flush()` when generated identifiers, database defaults, constraint outcomes, or typed error mapping depend on database execution.
- Catch expected SQLite/SQLAlchemy exceptions inside repository methods and translate them to stable repository/domain errors with exception chaining.
- Services, writer loops, routers, and API layers must not import or catch `IntegrityError`, `DBAPIError`, `SQLAlchemyError`, or SQLite driver exceptions.
- Keep services free of accumulated ad-hoc SQL; services may choose repositories, transaction scope, and domain decisions.
- Do not return live ORM entities directly to API responses. Convert to DTO/Pydantic/read models before crossing the API boundary.
- Avoid hidden lazy loading after session closure. Eagerly load required relationships or build response DTOs while the session is still valid.
- Keep repository methods explicit about whether they read, write, flush, or require a caller-owned transaction.

## 3. Engine And Session Lifecycle

- Configure each SQLAlchemy engine once at application startup or database component initialization, not per request, route, service, or repository call.
- Use one `Session` or `AsyncSession` per unit of work/request/task. Keep the lifetime short and visible.
- Never share `Session` or `AsyncSession` across concurrent tasks. Create separate sessions for concurrent work.
- Use context managers for sessions and transactions: `with Session(...)`, `async with AsyncSession(...)`, `session.begin()`, or `async with session.begin()`.
- Do not commit inside low-level repository methods unless that repository explicitly owns the entire unit of work. Prefer `flush()` when generated ids or constraint checks are needed before returning.
- For SQLite, choose sync SQLAlchemy for synchronous scripts, CLIs, or call chains. Choose async SQLAlchemy with `aiosqlite` when the application stack is async and database work must not block the event loop.
- Do not treat async SQLite as a multi-writer scaling strategy. Async prevents event-loop blocking; SQLite still allows only one writer at a time. When this project uses a writer queue, only the writer loop may own write sessions.

## 4. Single Writer Queue Pattern

When `CODEX_PROJECT.md` declares the SQLite single-writer queue pattern, one background writer task is the only normal runtime write path for SQLite. Producers enqueue explicit write commands or events into a bounded `asyncio.Queue`, and one writer loop flushes them to SQLite by batch size or timeout.

- Treat the single writer queue as the mandatory runtime write architecture only when `CODEX_PROJECT.md` declares that SQLite runtime writes use this pattern; otherwise follow the project-specific persistence policy declared there.
- Normal application code must not write to SQLite directly from routers, request dependencies, ordinary services, read repositories, or arbitrary background tasks.
- Runtime mutations must be represented as explicit write commands/events and enqueued into the writer queue.
- The writer loop is the only normal runtime owner of the write session factory.
- Read repositories must use only the read session factory and must not execute `INSERT`, `UPDATE`, `DELETE`, DDL, or write-capable repository methods.
- Services that need mutations must enqueue commands instead of opening write sessions or calling mutating repositories directly.
- Direct write sessions are allowed only for startup migrations, maintenance scripts, test setup, or explicitly documented emergency/admin paths.
- This architecture assumes one FastAPI worker/process. If deployment changes to multiple workers, the single-writer guarantee becomes process-local and must be redesigned or explicitly accepted.
- Implement the writer as a managed single-writer actor owned by application lifespan or an explicit database component lifecycle. A `while` loop that waits on `await queue.get()` is acceptable when it is not a polling loop.
- Do not poll `queue.empty()` with sleeps. Use `await queue.get()`, batch flush timeouts, and queue shutdown semantics instead.
- `asyncio.Event` may be used for auxiliary lifecycle signals such as pause/resume, started/stopped, or flush requests. Do not use an `Event` as the only stop mechanism for the writer loop when `Queue.shutdown()` is available.
- A pause/resume `Event` may gate processing before the next item or next batch. Clearing that event must not be expected to wake a task already blocked on `queue.get()` unless the loop explicitly waits on both the queue and the event.
- Prefer `queue.shutdown(immediate=False)`, `queue.join()`, and awaiting the writer task for graceful stop and drain. Use forced cancellation only as a documented emergency path.
- For restart, stop the current writer task completely and start a new lifecycle. Do not try to restart a completed task or reuse a queue that has already been shut down.
- Keep an explicit writer state such as `STARTING`, `RUNNING`, `PAUSED`, `STOPPING`, and `STOPPED` when start, stop, pause, resume, or restart can be called by application lifecycle code.
- Store a strong reference to the writer task or manage it through structured concurrency; do not create fire-and-forget writer tasks.
- Use `NullPool` for the write engine when the project intentionally wants every batch to use a short-lived write connection that is closed after commit or rollback.
- `NullPool` does not provide parallel writes. It is a lifecycle and lock-hygiene choice.
- The writer loop is the application-level serialization point. SQLite still allows only one active write transaction at a time.
- Use a bounded `asyncio.Queue` unless the project has a documented reason for unbounded buffering.
- Define backpressure behavior when the queue is full: wait, reject with a typed overload error, drop low-priority work, persist elsewhere, or use another project-approved policy.
- Treat an in-memory queue as non-durable. If writes must survive process crashes, use a durable source of truth, a replayable upstream, or a project-approved persistent queue.
- Batch writes by explicit size and timeout. Flush the final partial batch during graceful shutdown.
- Keep each batch transaction short: validate and prepare payloads before opening the transaction, write the batch, commit, then run post-commit side effects.
- Do not perform HTTP calls, sleeps, cache invalidation, filesystem scans, or slow computations inside the batch write transaction.
- If one item in a batch fails, the writer must have a documented failure policy: roll back the whole batch, split and retry, move failed items to a dead-letter path, log and continue only for explicitly safe events, or fail the writer task.
- Use database constraints and idempotency or deduplication keys for correctness. Queue ordering alone is not a substitute for uniqueness and consistency constraints.
- If API handlers return before the batch is committed, document the operation as accepted/enqueued rather than committed. Do not promise read-after-write consistency unless the handler waits for the specific write to be flushed and committed.
- If a caller must know the committed result, the queued command must carry an acknowledgement/future that is completed only after commit or failed after rollback/failure.
- On shutdown, stop accepting new items, drain or explicitly abandon the queue according to project policy, flush pending items, call `task_done()` correctly when `Queue.join()` is used, and close the write engine.
- Cancellation handling must use `try`/`finally` so the last batch can be committed or rolled back safely before the writer task exits.

## 5. SQLite PRAGMA Configuration

- Enable `PRAGMA foreign_keys=ON` on every connection. It is connection-local and cannot be assumed from schema definitions.
- Consider `PRAGMA journal_mode=WAL` for app-style file databases that need concurrent readers while writes occur.
- Configure `PRAGMA busy_timeout` so writer contention fails predictably instead of failing immediately under transient locks.
- Keep PRAGMA setup centralized in engine/connection wiring and cover it with integration tests.
- Do not scatter raw PRAGMA calls across repositories, services, routes, migrations, or business code.
- Verify PRAGMA values through a real connection in tests, not by checking only configuration constants.

## 6. SQLite Locking And Concurrency

- SQLite allows many readers but only one writer. Design write paths as short critical sections. When the project uses the writer queue, application code must not bypass it with direct writes.
- Keep write transactions short: prepare inputs before opening the transaction, persist changes, then commit.
- Do not perform external HTTP calls, slow computations, sleeps, cache calls, filesystem scans, or network operations while holding a write transaction.
- Avoid long-lived sessions and implicit transactions. Close sessions promptly after the unit of work.
- Expect lock behavior to differ between in-memory and file databases; test locking against a temporary file database.
- Recommend a server database when the expected workload requires many concurrent writers, long write transactions, or cross-process write-heavy coordination.

## 7. Raw SQL Migrations

- Use the migration tool declared in `CODEX_PROJECT.md`. When the active project declares raw SQL migrations, use the project migration runner and do not introduce or replace migration tooling without explicit user approval.
- Keep migration scripts ordered, deterministic, idempotency-aware, and manually reviewed. Do not edit already-applied migration files without an explicit checksum/history decision.
- Migration functions receive the caller-owned connection declared by the project migration runner. They must not call `commit()`, `rollback()`, or `close()` unless that runner explicitly requires it.
- Use `sqlalchemy.text()` with bound parameters for raw SQL that includes values.
- For SQLite schema changes that `ALTER TABLE` cannot perform directly, use the table-rebuild pattern: create a new table with the target schema, copy mapped data explicitly, recreate indexes/constraints/triggers, drop the old table, and rename the new table.
- Never silently drop data during rebuilds. Any omitted column, lossy conversion, deduplication, or default fill must be deliberate and visible in the migration body and review.
- Migration tests must apply migrations to a fresh temporary database and verify schema, constraints, data preservation, rollback behavior where supported, and migration history.

## 8. Query Correctness And Performance

- Use SQLAlchemy expressions or parameterized `text()` queries. Never interpolate user input with f-strings, `.format()`, `%`, or string concatenation.
- Use explicit indexes for lookup, join, filtering, ordering, and uniqueness paths that matter to behavior or latency.
- Use uniqueness constraints and check constraints for invariants; do not rely only on application pre-checks.
- Let repositories expose persistence outcomes through stable typed repository/domain errors. Repository methods must flush and map expected `IntegrityError` and other SQLite/SQLAlchemy exceptions before returning.
- Avoid N+1 queries. Use explicit eager loading, aggregate queries, or repository methods that return pre-shaped read models.
- Use pagination for list endpoints and repository list methods. Define stable ordering before applying `limit`/`offset` or cursor logic.
- Use `EXPLAIN QUERY PLAN` for suspicious slow SQLite queries and verify that expected indexes are used.
- Account for SQLite type affinity: booleans are stored as integers, datetime storage must be explicit and consistent, `Decimal`/money should not depend on binary float, JSON behavior depends on storage and functions available, and text comparisons are case-sensitive unless collation or normalization says otherwise.

## 9. Transactions And Consistency

- Put read-modify-write operations inside one transaction. Do not split the read and write across independent sessions or commits. When the writer queue is used, any correctness-critical read required for a mutation must run inside the writer loop transaction or be protected by database constraints.
- Use database constraints to protect invariants under concurrency. Pre-checks are useful for clearer errors, but they are not correctness boundaries.
- Do not rely only on a pre-check before insert/update; repository write methods must flush and translate any expected constraint violation before returning.
- Keep transaction ownership clear: service/unit-of-work code should own multi-repository commits; repositories should not surprise callers with commits.
- Caller-owned transactions control commit and rollback, while repositories remain responsible for persistence exception translation.
- Perform cache invalidation only after a successful commit. If the transaction rolls back, cache state must remain unchanged.
- Reference the active cache policy declared by `CODEX_PROJECT.md`; use the active cache and FastAPI skills for cache keys, TTLs, tags, and invalidation. Do not duplicate or fork those rules here.

## 10. Testing Requirements

- Apply `python-testing` for general pytest, pytest-asyncio, fixture, coverage, and assertion rules.
- Use a temporary file-based SQLite database when behavior depends on WAL, locking, multiple connections, connection pooling, PRAGMA settings, or the read/write engine split.
- Use in-memory SQLite only for isolated single-connection repository tests where connection-local behavior is irrelevant.
- Verify `PRAGMA foreign_keys`, constraints, rollback behavior, repository queries, pagination/order behavior, writer queue flush behavior where used, and fresh-database migration application.
- When the writer uses pause/resume events, test pause, resume, shutdown drain, and restart behavior without real sleeps.
- Do not mock SQLAlchemy for repository integration tests. Use the real engine/session/connection path with temporary database files.
- Test expected SQLite constraint failures through repository methods and assert typed repository/domain errors.
- Verify that raw SQLAlchemy, DBAPI, or SQLite driver exceptions do not escape repository public methods.
- Test migrations through the migration runner or the same connection contract the application uses, not by importing only helper functions.

## 11. Review Workflow

When reviewing SQLAlchemy + SQLite code:

- Load `references/patterns-and-review.md` for concrete anti-patterns and the final review checklist.
- Apply `python-core`, `python-testing`, and `python-sqlalchemy-core` together with this skill.
- Inspect models, repositories, session/engine setup, raw SQL migrations, settings, tests, existing DB conventions, and the runtime write policy declared in `CODEX_PROJECT.md`. Inspect writer queue code only when that policy enables the single-writer queue pattern or the task directly touches it.
- Verify that SQL/ORM details stay inside repositories and do not leak into routers or unrelated services.
- Verify that repositories flush and translate expected SQLAlchemy/SQLite exceptions to typed repository/domain errors.
- Verify that services, writer loops, routers, and API layers do not catch SQLAlchemy or SQLite driver exceptions.
- Verify that sessions are scoped to one unit of work, request, task, or writer batch and are not shared across concurrent tasks.
- Verify that transaction boundaries are explicit and write transactions are short.
- Verify that the implementation follows the runtime write policy declared in `CODEX_PROJECT.md`. Direct sessions, unit-of-work writes, and single-writer queues are separate supported policies; do not require queue architecture when another policy is active.
- When `CODEX_PROJECT.md` declares `Runtime write policy: single writer queue`, also verify that:
  - all normal runtime SQLite mutations go through the single writer queue;
  - routers, request dependencies, ordinary services, read repositories, and arbitrary background tasks do not open write sessions or call mutating repositories directly;
  - direct write access exists only for startup migrations, maintenance scripts, test setup, or explicitly documented emergency/admin paths;
  - the writer loop is the only normal runtime owner of the write session factory, batch transaction boundary, queue drain behavior, shutdown behavior, and failure policy;
  - the deployment assumption is compatible with a process-local writer queue, and multi-worker deployment is redesigned or explicitly accepted;
  - `asyncio.Event`, stop/restart behavior, queued-write semantics, acknowledgement behavior, backpressure, batch flushing, and failure handling follow the queue policy.
- Verify that external HTTP calls, slow computations, sleeps, cache calls, or network operations do not happen inside DB write transactions.
- Verify that `PRAGMA foreign_keys=ON` is configured on every connection.
- Verify that WAL, busy timeout, and other PRAGMA settings are centralized and tested when used.
- Verify that raw SQL migrations are ordered, deterministic, manually reviewed, and tested against a fresh temporary DB.
- Verify that query code is parameterized and does not use f-strings or string concatenation with user-controlled input.
- Verify that repository integration tests use real SQLite behavior instead of mocking SQLAlchemy.
