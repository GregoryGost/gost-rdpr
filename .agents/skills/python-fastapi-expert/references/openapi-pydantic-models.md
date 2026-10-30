# OpenAPI Pydantic Models

Load this file when creating, changing, or reviewing FastAPI Pydantic request/response models, OpenAPI schemas, endpoint metadata, or API contract tests.

## Baseline Rules

* Treat public Pydantic schemas as HTTP contract models, not as internal DTOs.
* Keep request models, response models, internal service DTOs, and SQLAlchemy/SQLModel database models separate.
* Every field exposed through OpenAPI must have a meaningful `Field(description=...)`.
* Prefer explicit examples for fields that clients must construct or interpret.
* Use model-level `json_schema_extra` for complete request/response examples.
* Use validation constraints directly in schema fields when the constraint is part of the API contract.
* Do not expose internal implementation details, ORM relationship names, secrets, raw tokens, internal IDs, or internal-only flags.
* Review OpenAPI output when schema changes affect clients, generated SDKs, external integrations, or backward compatibility.

## Field Documentation Rules

Each public field should document:

* business meaning;
* value format;
* unit of measurement, if applicable;
* allowed range or length, if applicable;
* enum/status semantics, if applicable;
* nullability semantics;
* whether the field is client-provided, server-generated, or read-only;
* privacy/security limitations, when relevant.

Bad:

```python
from pydantic import BaseModel, Field


class UserRead(BaseModel):
    """Публичная модель пользователя."""

    id: int = Field(description="ID")
    status: str = Field(description="Status")
```

Good:

```python
from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field


class UserStatus(StrEnum):
    """Статус пользователя в публичном API."""

    ACTIVE = "active"
    BLOCKED = "blocked"


class UserRead(BaseModel):
    """Публичная модель пользователя."""

    model_config = ConfigDict(
        json_schema_extra={
            "examples": [
                {
                    "id": 1001,
                    "email": "user@example.test",
                    "status": "active",
                    "created_at": "2026-06-19T12:30:00Z",
                }
            ]
        }
    )

    id: int = Field(
        description="Server-generated stable user identifier.",
        examples=[1001],
        ge=1,
    )
    email: str = Field(
        description="User email address used for notifications and login.",
        examples=["user@example.test"],
        max_length=320,
    )
    status: UserStatus = Field(
        description="Current account state. `active` users can use the API; `blocked` users cannot authenticate.",
        examples=[UserStatus.ACTIVE],
    )
    created_at: datetime = Field(
        description="UTC timestamp when the user record was created by the server.",
        examples=["2026-06-19T12:30:00Z"],
    )
```

## Request And Response Model Separation

Do not reuse one schema for create, update, patch, list item, detail response, and internal service data when their contracts differ.

Bad:

```python
from pydantic import BaseModel


class User(BaseModel):
    """Плохо: одна модель используется для всех API-контрактов."""

    id: int | None = None
    email: str
    password: str | None = None
    is_admin: bool = False
```

Good:

```python
from pydantic import BaseModel, ConfigDict, Field


class UserCreateRequest(BaseModel):
    """Тело запроса создания пользователя."""

    model_config = ConfigDict(
        json_schema_extra={
            "examples": [
                {
                    "email": "user@example.test",
                    "password": "correct-horse-battery-staple",
                }
            ]
        }
    )

    email: str = Field(
        description="Email address for the new user account.",
        examples=["user@example.test"],
        max_length=320,
    )
    password: str = Field(
        description="Initial password. It is accepted only in requests and is never returned.",
        examples=["correct-horse-battery-staple"],
        min_length=12,
        max_length=128,
    )


class UserUpdateRequest(BaseModel):
    """Тело запроса обновления пользователя."""

    email: str | None = Field(
        default=None,
        description="New email address. If omitted, the current email is not changed.",
        examples=["new-user@example.test"],
        max_length=320,
    )


class UserReadResponse(BaseModel):
    """Ответ с публичными данными пользователя."""

    id: int = Field(
        description="Server-generated stable user identifier.",
        examples=[1001],
        ge=1,
    )
    email: str = Field(
        description="Email address of the user.",
        examples=["user@example.test"],
        max_length=320,
    )
```

## Path, Query, Header, And Body Metadata

Use `Annotated` for HTTP parameters with metadata and validation.

```python
from typing import Annotated

from fastapi import Body, Header, Path, Query


UserIdPath = Annotated[
    int,
    Path(
        title="User ID",
        description="Stable server-generated identifier of the user.",
        examples=[1001],
        ge=1,
    ),
]

PageQuery = Annotated[
    int,
    Query(
        description="One-based page number for paginated list responses.",
        examples=[1],
        ge=1,
    ),
]

RequestIdHeader = Annotated[
    str | None,
    Header(
        alias="X-Request-ID",
        description="Optional client-provided request identifier used for tracing.",
        examples=["req-20260619-001"],
        max_length=128,
    ),
]

UserCreateBody = Annotated[
    UserCreateRequest,
    Body(
        description="User creation payload.",
        examples=[
            {
                "email": "user@example.test",
                "password": "correct-horse-battery-staple",
            }
        ],
    ),
]
```

## Endpoint Metadata

Public path operations should expose enough metadata for OpenAPI consumers.

```python
from fastapi import APIRouter, status

router = APIRouter(prefix="/users", tags=["users"])


@router.post(
    "",
    response_model=UserReadResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create user",
    description="Create a new user account and return its public representation.",
    response_description="Created user.",
    responses={
        409: {
            "model": ErrorResponse,
            "description": "A user with this email already exists.",
        },
    },
)
async def create_user(payload: UserCreateBody) -> UserReadResponse:
    """Создать пользователя."""
    ...
```

## Error Models

Use stable error response models for documented non-2xx responses.

* Keep error codes stable and machine-readable.
* Do not expose raw exception strings, SQL details, stack traces, internal URLs, or internal service names.
* Document important 400, 401, 403, 404, 409, 422, 429, and 5xx responses when clients must handle them.

```python
from pydantic import BaseModel, ConfigDict, Field


class ErrorResponse(BaseModel):
    """Стандартная ошибка публичного API."""

    model_config = ConfigDict(
        json_schema_extra={
            "examples": [
                {
                    "code": "user.email_already_exists",
                    "message": "A user with this email already exists.",
                }
            ]
        }
    )

    code: str = Field(
        description="Stable machine-readable error code.",
        examples=["user.email_already_exists"],
    )
    message: str = Field(
        description="Human-readable client-safe error message.",
        examples=["A user with this email already exists."],
    )
```

## Nullable And Optional Fields

* `field: str | None = None` means the field can be omitted and can be null.
* `field: str | None` means the field is required but can be null.
* Document nullability semantics when clients need to distinguish omitted values from explicit null.
* For PATCH requests, use dedicated patch/update models and document whether `None` clears a value or means no change.

Bad:

```python
from pydantic import BaseModel


class UserPatchRequest(BaseModel):
    """Плохо: неясно, что означает None."""

    display_name: str | None = None
```

Good:

```python
from pydantic import BaseModel, Field


class UserPatchRequest(BaseModel):
    """Тело частичного обновления пользователя."""

    display_name: str | None = Field(
        default=None,
        description="New display name. If omitted, the value is not changed. If set to null, the display name is cleared.",
        examples=["Gregory"],
        max_length=120,
    )
```

## OpenAPI Review Checklist

* [ ] Public request and response schemas are separate from DB models and internal DTOs.
* [ ] Every public field has a meaningful `Field(description=...)`.
* [ ] Important fields have `examples=[...]`.
* [ ] Complete body examples are present through `model_config = ConfigDict(json_schema_extra={...})` where useful.
* [ ] Field constraints are encoded in schemas when they are part of the API contract.
* [ ] Path/query/header/body parameters use `Annotated[..., Path/Query/Header/Body(...)]` when metadata or validation is needed.
* [ ] Endpoint decorators define accurate `response_model`, `status_code`, `summary`, `description`, `response_description`, and `responses`.
* [ ] Important non-2xx responses use stable error models.
* [ ] Sensitive fields and internal implementation details are not exposed in schemas or examples.
* [ ] Nullable and optional fields have intentional semantics.
* [ ] OpenAPI changes are covered by tests when they affect clients, generated SDKs, integrations, or backward compatibility.
