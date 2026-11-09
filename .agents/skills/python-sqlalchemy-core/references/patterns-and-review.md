# SQLAlchemy Core Patterns And Review

Load this file when implementing or reviewing SQLAlchemy repositories, session lifecycle, transactions, query behavior, error mapping, migration-policy coordination, or DB integration tests that are not specific to one database backend.

This file contains concrete bad/good examples and the final review checklist. The main rules remain in `../SKILL.md`.

## Negative And Positive Examples

### Engine Or Session Per Request

Bad:

```python
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine


async def get_session() -> AsyncSession:
    """Создать engine и session factory для одного запроса."""
    # Плохо: engine и session factory создаются на каждый вызов.
    engine = create_async_engine(settings.db_connection)
    session_factory = async_sessionmaker(engine)
    async with session_factory() as session:
        yield session
```

Good:

```python
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine


engine = create_async_engine(settings.db_connection)
session_factory = async_sessionmaker(engine, expire_on_commit=False)


async def get_session() -> AsyncSession:
    """Выдать короткоживущую сессию из общей фабрики."""
    async with session_factory() as session:
        yield session
```

### SQL In Service Layer

Bad:

```python
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession


class UserService:
    async def find_user(self, session: AsyncSession, email: str) -> UserRead | None:
        """Найти пользователя напрямую из service layer."""
        # Плохо: service накапливает SQL вместо обращения к repository.
        result = await session.execute(
            text("SELECT id, email FROM users WHERE email = :email"),
            {"email": email},
        )
        row = result.mappings().one_or_none()
        return UserRead(**row) if row else None
```

Good:

```python
from sqlalchemy.ext.asyncio import AsyncSession


class UserRepository:
    async def find_by_email(self, session: AsyncSession, email: str) -> UserRead | None:
        """Найти пользователя по email через repository."""
        ...


class UserService:
    def __init__(self, repository: UserRepository) -> None:
        self.repository = repository

    async def find_user(self, session: AsyncSession, email: str) -> UserRead | None:
        """Найти пользователя через repository."""
        return await self.repository.find_by_email(session, email)
```

### F-String SQL With User Input

Bad:

```python
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession


async def find_user(session: AsyncSession, email: str) -> UserDbo | None:
    """Найти пользователя по email."""
    # Плохо: пользовательский ввод попадает прямо в SQL.
    result = await session.execute(text(f"SELECT * FROM users WHERE email = '{email}'"))
    return result.scalar_one_or_none()
```

Good:

```python
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession


async def find_user(session: AsyncSession, email: str) -> UserDbo | None:
    """Найти пользователя по email безопасным параметризованным запросом."""
    result = await session.execute(
        text("SELECT * FROM users WHERE email = :email"),
        {"email": email},
    )
    return result.scalar_one_or_none()
```

### Repository Commits Unexpectedly

Bad:

```python
from sqlalchemy.ext.asyncio import AsyncSession


class UserRepository:
    async def create_user(self, session: AsyncSession, payload: UserCreate) -> UserDbo:
        """Создать пользователя и неожиданно завершить transaction."""
        user = UserDbo(email=payload.email)
        session.add(user)
        # Плохо: repository забирает transaction ownership у caller.
        await session.commit()
        return user
```

Good:

```python
from sqlalchemy.ext.asyncio import AsyncSession


class UserRepository:
    async def create_user(self, session: AsyncSession, payload: UserCreate) -> UserDbo:
        """Создать пользователя внутри transaction, которой владеет caller."""
        user = UserDbo(email=payload.email)
        session.add(user)
        await session.flush()
        return user
```

### SQLAlchemy Error Escapes Repository

Bad:

```python
from sqlalchemy.exc import IntegrityError


class UserService:
    async def create_user(self, session: AsyncSession, payload: UserCreate) -> UserRead:
        """Создать пользователя и преобразовать DB error в service layer."""
        try:
            user = await self.repository.create_user(session, payload)
            await session.flush()
        except IntegrityError as exc:
            # Плохо: service знает о SQLAlchemy и persistence constraints.
            raise EmailAlreadyExistsError from exc

        return UserRead.model_validate(user)
```

Good:

```python
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession


class UserRepository:
    async def create_user(self, session: AsyncSession, payload: UserCreate) -> UserDbo:
        """Создать пользователя и скрыть SQLAlchemy за repository boundary."""
        user = UserDbo(email=payload.email)
        session.add(user)

        try:
            await session.flush()
        except IntegrityError as exc:
            raise EmailAlreadyExistsError from exc

        return user


class UserService:
    async def create_user(self, session: AsyncSession, payload: UserCreate) -> UserRead:
        """Создать пользователя без зависимости от SQLAlchemy exceptions."""
        user = await self.repository.create_user(session, payload)
        return UserRead.model_validate(user)
```

Why this is good:

- Repository is the complete persistence boundary.
- The expected constraint is forced by `flush()` before the repository returns.
- Callers depend on a stable typed error instead of SQLAlchemy or driver exceptions.
- The caller-owned transaction still controls commit and rollback.

### External Work Inside Transaction

Bad:

```python
from sqlalchemy.ext.asyncio import AsyncSession


async def sync_issue(session: AsyncSession, issue_id: int) -> None:
    """Обновить задачу по данным внешней системы."""
    async with session.begin():
        # Плохо: transaction удерживается во время сетевого вызова.
        payload = await jira_client.get_issue(issue_id)
        await issue_repository.update_issue(session, issue_id=issue_id, payload=payload)
```

Good:

```python
from sqlalchemy.ext.asyncio import AsyncSession


async def sync_issue(session: AsyncSession, issue_id: int) -> None:
    """Получить внешние данные до короткой transaction."""
    payload = await jira_client.get_issue(issue_id)

    async with session.begin():
        await issue_repository.update_issue(session, issue_id=issue_id, payload=payload)
```

### Mocked Repository Test Mistaken For DB Coverage

Bad:

```python
async def test_user_service_creates_user(mock_user_repository) -> None:
    """Проверить создание пользователя через mock repository."""
    await service.create_user(email="user@example.test")

    # Плохо: этот тест не проверяет SQLAlchemy, constraints или transaction behavior.
    mock_user_repository.create_user.assert_awaited_once()
```

Good:

```python
async def test_user_repository_rejects_duplicate_email(db_session: AsyncSession) -> None:
    """Проверить constraint уникальности на реальной БД теста."""
    async with db_session.begin():
        await repository.create_user(db_session, UserCreate(email="user@example.test"))

    with pytest.raises(EmailAlreadyExistsError):
        async with db_session.begin():
            await repository.create_user(db_session, UserCreate(email="user@example.test"))
```

## Review Checklist

- [ ] Engine and session factories are configured once, not per request or repository call.
- [ ] Session lifetime is scoped to one unit of work, request, task, or explicit batch.
- [ ] `Session` or `AsyncSession` is not shared across concurrent tasks.
- [ ] SQLAlchemy expressions and raw SQL stay inside repositories.
- [ ] Routers do not contain SQLAlchemy code.
- [ ] Services do not accumulate ad-hoc SQL.
- [ ] Repository methods are explicit about read/write/flush/transaction expectations.
- [ ] Repository public methods form a complete persistence boundary; SQLAlchemy and driver exceptions do not escape them.
- [ ] Repository write methods flush when generated values, constraints, or error mapping require database execution.
- [ ] Expected DB failures are translated inside repositories to stable repository/domain errors with exception chaining.
- [ ] Services and routers do not import or catch SQLAlchemy or driver exceptions.
- [ ] Low-level repositories do not commit unexpectedly.
- [ ] Read-modify-write operations run inside one transaction.
- [ ] External HTTP calls, sleeps, filesystem scans, cache invalidation, and slow computation do not happen inside write transactions.
- [ ] User-controlled values use SQLAlchemy expressions or bound parameters.
- [ ] Dynamic sort/filter/column/table inputs use allowlists.
- [ ] Database constraints protect invariants that matter under concurrency.
- [ ] ORM entities are not returned directly as public API responses.
- [ ] Hidden lazy loading after session closure is avoided.
- [ ] Repository integration tests use a real engine/session/connection path for the active database backend.
- [ ] Repository integration tests assert typed errors and verify that raw SQLAlchemy exceptions do not escape.
- [ ] Unit tests with mocked repositories are not counted as repository SQL coverage.
- [ ] Migration behavior follows the policy declared in `CODEX_PROJECT.md`.
- [ ] Backend-specific mechanics are handled by the active database-specific skill.
