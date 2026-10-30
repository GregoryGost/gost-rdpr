# Python FastAPI rules

Apply this rule when `CODEX_PROJECT.md` declares FastAPI active, or when the task changes FastAPI routers, dependencies, request/response models, OpenAPI metadata, lifespan, middleware, or FastAPI tests.

## Required skills

Use together with:

- `python-core`;
- `python-fastapi-expert`.

## Source of truth

Before changing FastAPI code:

1. Read `CODEX_PROJECT.md`.
2. Check FastAPI app entry point, router layout, dependency policy, settings, validation commands, and active overlays.
3. Inspect routers, dependencies, schemas, services, repositories, tests, and API documentation.
4. Use project-declared commands.

## Constraints

- Keep routers thin: parse HTTP input, resolve dependencies, and call service/domain code.
- Keep business rules in services or domain code, not routers.
- Keep database query details in repositories or data-access modules.
- Keep public request/response schemas separate from database models and internal DTOs.
- Keep status codes, response models, documented errors, and OpenAPI metadata intentional.
- Use `BackgroundTasks` only for lightweight post-response work.
- Use project worker/queue mechanisms for durable, scheduled, long-running, or retryable jobs.
