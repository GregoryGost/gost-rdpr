# Security Negative Examples

Load this file when implementing or reviewing one of these risky patterns. Keep examples aligned with repository conventions before copying any shape into code.

## Router-Only Authorization

Bad:

```python
from fastapi import APIRouter, Depends, HTTPException


router = APIRouter()


@router.delete("/projects/{project_id}")
async def delete_project(project_id: int, user: CurrentUser = Depends(get_current_user)) -> None:
    """Удалить проект после поверхностной проверки."""
    if not user.is_authenticated:
        raise HTTPException(status_code=401)
    await project_service.delete(project_id)
```

Good:

```python
class ProjectPolicy:
    def can_delete(self, user: CurrentUser, project: ProjectDto) -> bool:
        """Проверить право удаления проекта."""
        return user.is_active and project.owner_id == user.id


class ProjectService:
    async def delete_for_user(self, project_id: int, user: CurrentUser) -> None:
        """Удалить проект только после проверки владения."""
        project = await self.repository.get_by_id(project_id)
        if project is None or not self.policy.can_delete(user, project):
            raise ForbiddenError("project_delete_forbidden")
        await self.repository.delete(project_id)
```

## Trusting Client `tenant_id` Or `user_id`

Bad:

```python
class TaskService:
    async def create_task(self, payload: TaskCreate) -> TaskDto:
        """Создать задачу из пользовательского payload."""
        # Плохо: пользователь сам выбирает tenant_id и owner_id.
        return await self.repository.create(
            tenant_id=payload.tenant_id,
            owner_id=payload.user_id,
            title=payload.title,
        )
```

Good:

```python
class TaskService:
    async def create_task(self, payload: TaskCreate, auth: AuthContext) -> TaskDto:
        """Создать задачу в tenant из проверенного auth context."""
        return await self.repository.create(
            tenant_id=auth.tenant_id,
            owner_id=auth.user_id,
            title=payload.title,
        )
```

## F-String SQL

Bad:

```python
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession


async def find_user(session: AsyncSession, email: str) -> UserDbo | None:
    """Найти пользователя по email."""
    # Плохо: пользовательский ввод встроен в SQL строку.
    result = await session.execute(text(f"SELECT * FROM users WHERE email = '{email}'"))
    return result.scalar_one_or_none()
```

Good:

```python
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession


async def find_user(session: AsyncSession, email: str) -> UserDbo | None:
    """Найти пользователя параметризованным запросом."""
    result = await session.execute(select(UserDbo).where(UserDbo.email == email))
    return result.scalar_one_or_none()
```

## Wildcard CORS With Credentials

Bad:

```python
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware


app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
```

Good:

```python
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware


app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH", "DELETE"],
    allow_headers=["Authorization", "Content-Type"],
)
```

## Logging `Authorization` Header

Bad:

```python
import logging


logger = logging.getLogger(__name__)


async def call_partner(headers: dict[str, str]) -> None:
    """Вызвать partner API."""
    # Плохо: Authorization попадет в лог.
    logger.info("partner request headers=%s", headers)
```

Good:

```python
import logging


logger = logging.getLogger(__name__)


async def call_partner(headers: dict[str, str]) -> None:
    """Вызвать partner API без записи секретов."""
    sensitive_headers = {"authorization", "cookie", "set-cookie"}
    safe_headers = {
        name: value
        for name, value in headers.items()
        if name.lower() not in sensitive_headers
    }
    logger.info("partner request headers=%s", safe_headers)
```

## Fetching Arbitrary User URL With HTTPX

Bad:

```python
import httpx


async def fetch_preview(url: str) -> bytes:
    """Скачать страницу предпросмотра."""
    # Плохо: пользователь может запросить внутренний адрес.
    async with httpx.AsyncClient() as client:
        response = await client.get(url)
        response.raise_for_status()
        return response.content
```

Good:

```python
from urllib.parse import urlparse

import httpx


ALLOWED_PREVIEW_HOSTS = {"example.com", "cdn.example.com"}


def validate_preview_url(url: str) -> str:
    """Проверить URL предпросмотра по allowlist."""
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        raise ValueError("unsupported_url_scheme")
    if parsed.hostname not in ALLOWED_PREVIEW_HOSTS:
        raise ValueError("unsupported_url_host")
    return url


async def fetch_preview(client: httpx.AsyncClient, url: str) -> bytes:
    """Скачать предпросмотр только после проверки URL."""
    response = await client.get(validate_preview_url(url), follow_redirects=False)
    response.raise_for_status()
    return response.content
```

## Cache Key Missing Tenant Or User Scope

Bad:

```python
from cashews import cache


class ReportService:
    @cache(ttl="5m", key="v1:report:{report_id}")
    async def get_report(self, tenant_id: str, user_id: int, report_id: int) -> ReportRead:
        """Получить отчет для пользователя."""
        return await self.repository.get_report(tenant_id, user_id, report_id)
```

Good:

```python
from cashews import cache


class ReportService:
    @cache(ttl="5m", key="v1:tenant:{tenant_id}:user:{user_id}:report:{report_id}")
    async def get_report(self, tenant_id: str, user_id: int, report_id: int) -> ReportRead:
        """Получить отчет с областью кеша по tenant и пользователю."""
        return await self.repository.get_report(tenant_id, user_id, report_id)
```
