---
name: python-fastapi-expert
description: "Use for FastAPI routers, dependencies, schemas, OpenAPI contracts, lifespan, background tasks, and framework review."
---

# Python FastAPI Expert

Use this skill when `CODEX_PROJECT.md` declares FastAPI active, or when a task changes FastAPI routers, dependencies, request/response models, OpenAPI metadata, lifespan, middleware, background work, or FastAPI tests.

Apply `CODEX_PROJECT.md`, `python-core`, `.codex/rules/python_fastapi.md`, and this skill together.

Before using this skill to modify code, inspect relevant Python source files, tests, settings, and project documentation. Do not act from assumptions about the codebase.

Load references when needed:

- `references/openapi-pydantic-models.md` for Pydantic request/response models, OpenAPI schema details, endpoint metadata, and API contract tests.

## Core FastAPI Responsibilities

- Treat FastAPI routes as the HTTP boundary, not as the business-logic layer.
- Use `APIRouter`, dependencies, request/response schemas, and status metadata to express the public API contract.
- Keep business rules in services or domain code.
- Keep SQL/ORM query details in repositories or data-access modules.
- Keep public API schemas separate from SQLAlchemy/SQLModel database models and internal DTOs.
- Keep async boundaries explicit and compatible with the repository's database drivers and external clients.

## FastAPI Expert Guidelines

- Use `async def` when a path operation, dependency, service, or repository awaits async I/O.
- Use normal `def` only for synchronous libraries or CPU/blocking work that is safe for the selected execution boundary.
- Do not instantiate services inside routes. Use `Depends()` or the project dependency container/factory pattern.
- Raise `HTTPException` or domain-specific errors for business/resource failures such as 404, 403, 409, and integration failures.
- Do not manually reimplement FastAPI request validation behavior for 422 unless the API contract requires a custom validation-error handler.
- Use FastAPI `BackgroundTasks` only for lightweight post-response work that does not require durable retries.
- Use the project worker or queue mechanism for durable, long-running, scheduled, or retryable jobs.
- Keep lifespan/startup/shutdown ownership explicit for app-wide resources.

## Plan Mode

Before implementation:

1. Read documentation and source files for the affected resource.
2. Inspect existing routers, services, repositories, schemas, tests, settings, and API documentation.
3. Design the flow through Router -> Service/domain -> Repository/integration boundary.
4. Identify request and response Pydantic models.
5. Identify transaction boundaries and error/status behavior.
6. Identify required tests and validation commands.

## Act Mode

When implementing:

1. Keep route functions thin: validate HTTP input, resolve dependencies, and call service/domain code.
2. Put query details in repositories or data-access modules.
3. Keep API schemas stable and explicit.
4. Keep background work matched to the durability requirement.
5. Run or report project-declared lint, type-check, test, and build commands.
6. Ensure Swagger UI/OpenAPI output reflects request/response models, status codes, and documented errors.
7. Summarize API, DB, worker, schema, and test changes.
8. Commit only when the user or repository workflow explicitly asks for it.

## Technical Expertise

- FastAPI: `APIRouter`, `Depends`, `HTTPException`, `BackgroundTasks`, lifespan, middleware, OpenAPI response models.
- Pydantic: public request/response schemas, validation constraints, examples, aliases, nullability, and schema metadata.
- SQLAlchemy / SQLModel: async sessions when async drivers are used, transaction boundaries, relationship loading strategies, lazy versus eager loading.
- Migrations: follow the repository migration policy. If the project uses raw SQL migration scripts, do not introduce Alembic.
- Asyncio: event loops, async I/O, threadpool boundaries, resource ownership, and concurrency patterns.

## Review Workflow

When reviewing FastAPI backend changes:

- Apply `python-core` and active Python testing rules together with this skill.
- Inspect routers, dependencies, schemas, services, repositories, settings, tests, and documentation before judging the change.
- Verify that routes stay thin: HTTP input handling, dependency resolution, and a call into service/domain code only.
- Verify that business rules live in services or domain code, not routers.
- Verify that SQL/ORM query details live in repositories, not services or routers.
- Verify that request and response schemas are separated from persistence models.
- Verify that response models, status codes, and documented errors match the API contract.
- Verify that transaction boundaries are explicit.
- Verify that background work uses the correct FastAPI, worker, or queue mechanism.
- Review tests together with implementation changes: API contract tests, service tests, repository integration tests, and schema regression tests where applicable.

## HTTP Models And OpenAPI Schemas

Treat Pydantic request and response models as the public HTTP contract used by OpenAPI, Swagger UI, client generators, tests, and external integrators.

For concrete examples, review checklist, and anti-patterns, load `references/openapi-pydantic-models.md` when creating or reviewing FastAPI request/response schemas.

- Keep API schemas separate from SQLAlchemy/SQLModel database models and internal domain objects.
- Create explicit request and response models for public endpoints when their contracts differ.
- Every externally visible Pydantic field should have a meaningful description when business meaning, format, constraints, or visibility are not obvious.
- Add examples where concrete values improve API usability, especially identifiers, statuses, enums, timestamps, pagination, filters, and integration-facing fields.
- Use model-level examples for request and response bodies that clients are expected to copy or generate.
- Use validation constraints in schema fields when they are part of the HTTP contract.
- Use `typing.Annotated` with `Path`, `Query`, `Header`, `Cookie`, `Body`, `Form`, and `File` for HTTP parameters that need descriptions, examples, aliases, deprecation flags, or validation constraints.
- Use explicit `response_model`, `status_code`, `responses`, `summary`, `description`, and `response_description` when generated defaults are not enough.
- Document important non-2xx responses with stable error models when clients must handle them.
- Avoid leaking internal field names, database terminology, stack traces, ORM relationships, secrets, tokens, or implementation-only fields into public API schemas.
- Review OpenAPI changes together with tests when they affect clients, generated SDKs, external integrations, or backward compatibility.

## Review Checklist

- [ ] FastAPI is active in `CODEX_PROJECT.md` or directly touched by the task.
- [ ] Routers stay thin and delegate business behavior.
- [ ] Dependencies are explicit and follow project conventions.
- [ ] Request/response models are separated from persistence models and internal DTOs.
- [ ] Response models, status codes, documented errors, and OpenAPI metadata match the API contract.
- [ ] Transaction boundaries are explicit and not hidden in unrelated repository calls.
- [ ] Background work uses the correct FastAPI, worker, or queue mechanism.
- [ ] Tests cover API contracts, service behavior, repository integration, and schema changes where relevant.
