# SQLAlchemy SQLite Patterns And Review

Load this file when implementing or reviewing SQLAlchemy + SQLite engines, repositories, raw SQL migrations, PRAGMA setup, transaction boundaries, single-writer queue behavior, or database integration tests.

This file contains concrete bad/good examples and the final review checklist. The main rules remain in `../SKILL.md`.

## Negative And Positive Examples

### Engine Or Session Per Request

Bad:

```python
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker


async def get_session() -> AsyncSession:
    """Создать новую сессию для одного HTTP-запроса."""
    # Плохо: engine и factory создаются на каждый запрос.
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

### Missing `PRAGMA foreign_keys`

Bad:

```python
async def create_child(session: AsyncSession, payload: ChildCreate) -> None:
    """Создать дочернюю запись без проверки внешнего ключа."""
    # Плохо: код полагается на ForeignKey в модели, но SQLite может не проверять его.
    session.add(ChildDbo(parent_id=payload.parent_id))
```

Good:

```python
from sqlalchemy import event


@event.listens_for(engine.sync_engine, "connect")
def configure_sqlite(dbapi_connection, connection_record) -> None:
    """Включить проверку внешних ключей для каждого SQLite connection."""
    del connection_record
    cursor = dbapi_connection.cursor()
    try:
        cursor.execute("PRAGMA foreign_keys=ON")
    finally:
        cursor.close()
```

### F-String SQL With User Input

Bad:

```python
async def find_user(session: AsyncSession, email: str) -> UserDbo | None:
    """Найти пользователя по email."""
    # Плохо: пользовательский ввод попадает прямо в SQL.
    result = await session.execute(text(f"SELECT * FROM users WHERE email = '{email}'"))
    return result.scalar_one_or_none()
```

Good:

```python
async def find_user(session: AsyncSession, email: str) -> UserDbo | None:
    """Найти пользователя по email безопасным параметризованным запросом."""
    result = await session.execute(
        text("SELECT * FROM users WHERE email = :email"),
        {"email": email},
    )
    return result.scalar_one_or_none()
```

### External HTTP Call Inside DB Transaction

Bad:

```python
async def sync_issue(session: AsyncSession, issue_id: int) -> None:
    """Обновить задачу по данным внешней системы."""
    async with session.begin():
        # Плохо: write transaction удерживается во время сетевого вызова.
        payload = await jira_client.get_issue(issue_id)
        await repository.update_issue(issue_id=issue_id, payload=payload)
```

Good:

```python
async def sync_issue(session: AsyncSession, issue_id: int) -> None:
    """Получить внешние данные до короткой write transaction."""
    payload = await jira_client.get_issue(issue_id)

    async with session.begin():
        await repository.update_issue(issue_id=issue_id, payload=payload)
```

### Repository Committing Unexpectedly

Bad:

```python
class UserRepository:
    async def create_user(self, payload: UserCreate) -> UserDbo:
        """Создать пользователя и скрыто завершить transaction."""
        user = UserDbo(email=payload.email)
        self.session.add(user)
        # Плохо: caller больше не контролирует unit of work.
        await self.session.commit()
        return user
```

Good:

```python
from sqlalchemy.exc import IntegrityError


class UserRepository:
    async def create_user(self, payload: UserCreate) -> UserDbo:
        """Создать пользователя внутри transaction вызывающего слоя."""
        user = UserDbo(email=payload.email)
        self.session.add(user)

        try:
            await self.session.flush()
        except IntegrityError as exc:
            raise EmailAlreadyExistsError from exc

        return user
```

Why this is good:

- Repository does not take commit ownership from the caller.
- `flush()` forces the expected constraint outcome before the method returns.
- SQLAlchemy remains hidden behind a stable repository/domain error.

### In-Memory DB Misuse For WAL Or Multi-Connection Behavior

Bad:

```python
async def test_wal_mode_with_memory_db() -> None:
    """Проверить WAL на in-memory базе."""
    # Плохо: in-memory SQLite не отражает file locking и WAL-сценарии.
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    ...
```

Good:

```python
async def test_wal_mode_with_file_db(tmp_path: Path) -> None:
    """Проверить WAL и несколько подключений на файловой SQLite базе."""
    db_path = tmp_path / "app.sqlite"
    engine = create_async_engine(f"sqlite+aiosqlite:///{db_path}")
    ...
```

### Write Session Exposed Outside Single Writer Queue

Bad:

```python
async def create_user_route(
    payload: UserCreateRequest,
    write_session: AsyncSession = Depends(get_write_session),
) -> UserRead:
    """Создать пользователя напрямую из HTTP handler."""
    # Плохо: HTTP handler обходит единственную runtime-точку записи.
    async with write_session.begin():
        user = await user_repository.create_user(write_session, payload)
    return UserRead.model_validate(user)
```

Good:

```python
async def create_user_route(
    payload: UserCreateRequest,
    writer_queue: UserWriterQueue = Depends(get_user_writer_queue),
) -> AcceptedResponse:
    """Поставить создание пользователя в очередь записи."""
    command = CreateUserCommand(
        email=payload.email,
        idempotency_key=payload.idempotency_key,
    )
    await writer_queue.enqueue(command)
    return AcceptedResponse(status="accepted")
```

Good when the API must wait for commit:

```python
async def create_user_route(
    payload: UserCreateRequest,
    writer_queue: UserWriterQueue = Depends(get_user_writer_queue),
) -> UserRead:
    """Создать пользователя и дождаться commit от writer loop."""
    command = CreateUserCommand(
        email=payload.email,
        idempotency_key=payload.idempotency_key,
    )
    user = await writer_queue.enqueue_and_wait(command)
    return UserRead.model_validate(user)
```

### Unbounded Writer Queue

Bad:

```python
writer_queue: asyncio.Queue[WriteCommand] = asyncio.Queue()
```

Good:

```python
writer_queue: asyncio.Queue[WriteCommand] = asyncio.Queue(
    maxsize=settings.sqlite_writer_queue_maxsize,
)
```

### Event Used As The Only Stop Mechanism

Bad:

```python
class BadWriter:
    async def run(self) -> None:
        """Запустить writer loop до сигнала остановки."""
        while not self.stop_event.is_set():
            # Плохо: stop_event не разбудит задачу, если очередь пуста.
            command = await self.queue.get()
            try:
                await self.process(command)
            finally:
                self.queue.task_done()
```

Good:

```python
class GoodWriter:
    async def run(self) -> None:
        """Запустить writer loop с pause/resume и graceful shutdown очереди."""
        try:
            while True:
                await self.resume_event.wait()

                try:
                    command = await self.queue.get()
                except asyncio.QueueShutDown:
                    break

                try:
                    await self.add_to_batch(command)
                    if self.should_flush():
                        await self.flush_batch()
                finally:
                    self.queue.task_done()
        finally:
            await self.flush_batch()

    async def stop(self) -> None:
        """Остановить writer после обработки уже принятых команд."""
        self.queue.shutdown(immediate=False)
        await self.queue.join()
        await self.writer_task
```

### Read-Modify-Write Split Around The Writer Queue

Bad:

```python
async def enqueue_user_creation(
    read_session: AsyncSession,
    writer_queue: UserWriterQueue,
    email: str,
) -> None:
    """Поставить создание пользователя в очередь после внешней pre-check проверки."""
    # Плохо: pre-check не является correctness boundary.
    exists = await user_read_repository.exists_by_email(read_session, email)
    if exists:
        raise EmailAlreadyExistsError

    await writer_queue.enqueue(CreateUserCommand(email=email))
```

Good:

```python
from sqlalchemy.exc import IntegrityError


class UserWriteRepository:
    async def create_user(
        self,
        write_session: AsyncSession,
        *,
        email: str,
        idempotency_key: str,
    ) -> UserDbo:
        """Создать пользователя и преобразовать constraint error внутри repository."""
        user = UserDbo(email=email, idempotency_key=idempotency_key)
        write_session.add(user)

        try:
            await write_session.flush()
        except IntegrityError as exc:
            raise EmailAlreadyExistsError from exc

        return user


async def writer_create_user(write_session: AsyncSession, command: CreateUserCommand) -> None:
    """Создать пользователя внутри writer transaction."""
    async with write_session.begin():
        await user_write_repository.create_user(
            write_session,
            email=command.email,
            idempotency_key=command.idempotency_key,
        )
```

Why this is good:

- The writer owns orchestration and the transaction, not SQLAlchemy error classification.
- The repository forces the constraint with `flush()` and exposes only a typed error.
- The service/writer layer does not import or catch SQLAlchemy exceptions.

### Enqueued Write Reported As Committed

Bad:

```python
async def create_event(writer_queue: EventWriterQueue, payload: EventCreateRequest) -> EventResponse:
    """Создать событие."""
    await writer_queue.enqueue(CreateEventCommand(payload=payload))
    # Плохо: ответ обещает уже созданную запись, хотя commit еще не выполнен.
    return EventResponse(status="created")
```

Good:

```python
async def create_event(writer_queue: EventWriterQueue, payload: EventCreateRequest) -> AcceptedResponse:
    """Принять событие к асинхронной записи."""
    await writer_queue.enqueue(CreateEventCommand(payload=payload))
    return AcceptedResponse(status="accepted")
```

## Review Checklist

Apply the general checklist to every SQLAlchemy + SQLite project. Apply the single-writer queue checklist only when `CODEX_PROJECT.md` declares `Runtime write policy: single writer queue` or the task directly reviews that architecture. When another runtime write policy is active, review that policy without requiring a writer queue.

### General SQLite Checklist

- [ ] SQL/ORM details stay in repositories; services own orchestration and transactions.
- [ ] Repository public methods form a complete persistence boundary; SQLAlchemy, DBAPI, and SQLite driver exceptions do not escape.
- [ ] Repository write methods flush when generated values, constraints, or error mapping require database execution.
- [ ] Expected persistence failures are translated inside repositories to stable repository/domain errors with exception chaining.
- [ ] Services, writer loops, routers, and API layers do not import or catch SQLAlchemy or SQLite driver exceptions.
- [ ] Engines are configured once; sessions are short-lived and not shared across concurrent tasks.
- [ ] Repositories do not commit unexpectedly.
- [ ] `PRAGMA foreign_keys=ON`, WAL choice, and `busy_timeout` are centralized and tested.
- [ ] Write transactions are short and contain no HTTP, cache, sleep, or slow external work.
- [ ] Raw SQL migrations are ordered, reviewed, checksum-safe, and preserve data explicitly.
- [ ] User input reaches SQL only through SQLAlchemy expressions or bound parameters.
- [ ] Constraints and indexes protect invariants and expected query paths.
- [ ] Lists are paginated with stable ordering; suspicious queries have `EXPLAIN QUERY PLAN` evidence.
- [ ] Cache invalidation happens only after successful commit and follows existing cashews rules.
- [ ] Integration tests use temporary file SQLite when PRAGMA, WAL, locking, or multiple connections matter.
- [ ] Repository integration tests assert typed repository/domain errors and verify that raw persistence exceptions do not escape.
- [ ] The implementation matches the runtime write policy declared in `CODEX_PROJECT.md`; direct sessions and unit-of-work writes are not rejected merely because they do not use a queue.

### Single-Writer Queue Checklist

Apply this subsection only when `CODEX_PROJECT.md` declares `Runtime write policy: single writer queue` or the task directly reviews that pattern.

- [ ] All normal runtime SQLite writes go through the single writer queue.
- [ ] Runtime mutations are modeled as explicit write commands/events.
- [ ] Routers, request dependencies, ordinary services, read repositories, and arbitrary background tasks do not open write sessions directly.
- [ ] The writer loop is the only normal runtime owner of the write session factory.
- [ ] Direct write access exists only for startup migrations, maintenance scripts, test setup, or explicitly documented admin/emergency paths.
- [ ] The architecture assumes one FastAPI worker/process; multi-worker deployment requires redesign or explicit acceptance of process-local writer queues.
- [ ] `NullPool` on the write engine is treated as short-lived write-connection hygiene, not parallel-write scaling.
- [ ] The writer queue is bounded or has a documented reason for being unbounded.
- [ ] Queue-full backpressure behavior is explicit and tested.
- [ ] The writer loop uses `await queue.get()` or queue shutdown semantics instead of polling `queue.empty()` with sleeps.
- [ ] If `asyncio.Event` is used, it is used for pause/resume or auxiliary lifecycle signals, not as the only stop mechanism.
- [ ] Stop/restart behavior uses queue shutdown, queue drain, task lifecycle, and resource cleanup.
- [ ] Batch flush behavior by size, timeout, and shutdown is tested.
- [ ] Writer failure policy is documented and tested for partial batch failures.
- [ ] API semantics distinguish enqueued/accepted writes from committed writes when handlers return before commit.
- [ ] Endpoints that require committed semantics wait for writer acknowledgement after commit.
- [ ] In-memory queued writes are not treated as durable unless the project has a replay/durability mechanism.
