# HTTPX Patterns And Review

Load this file when implementing examples, reviewing an integration client, or checking failure modes around lifecycle, timeouts, retries, rate limits, `429` handling, URL safety, logging, streaming, or DB transactions.

## Negative And Positive Examples

### AsyncClient Created Inside Every Request

Bad:

```python
import httpx


async def fetch_issue(issue_id: int) -> dict:
    """Получить задачу из внешней системы."""
    # Плохо: новый connection pool создается на каждый вызов.
    async with httpx.AsyncClient() as client:
        response = await client.get(f"https://tracker.example/issues/{issue_id}")
        response.raise_for_status()
        return response.json()
```

Good:

```python
import httpx


class TrackerClient:
    """Клиент для обращений к внешнему tracker API."""

    def __init__(self, client: httpx.AsyncClient) -> None:
        self._client = client

    async def fetch_issue(self, issue_id: int) -> dict:
        """Получить задачу через управляемый HTTPX client."""
        response = await self._client.get(f"/issues/{issue_id}")
        response.raise_for_status()
        return response.json()
```

### Timeout Omitted

Bad:

```python
import httpx


async def load_user(client: httpx.AsyncClient, user_id: str) -> dict:
    """Загрузить пользователя из внешней системы."""
    # Плохо: политика timeout не задана явно.
    response = await client.get(f"/users/{user_id}")
    response.raise_for_status()
    return response.json()
```

Good:

```python
import httpx


timeout = httpx.Timeout(connect=2.0, read=5.0, write=5.0, pool=1.0)


async def load_user(client: httpx.AsyncClient, user_id: str) -> dict:
    """Загрузить пользователя с явной политикой timeout."""
    response = await client.get(f"/users/{user_id}", timeout=timeout)
    response.raise_for_status()
    return response.json()
```

### Ad-Hoc Retry Instead Of httpx-retries

Bad:

```python
import asyncio

import httpx


async def load_user(client: httpx.AsyncClient, user_id: str) -> dict:
    """Загрузить пользователя с самодельным retry."""
    # Плохо: ad-hoc retry дублирует RetryTransport и легко теряет Retry-After/budget.
    for _ in range(3):
        response = await client.get(f"/users/{user_id}")
        if response.status_code not in {429, 502, 503, 504}:
            response.raise_for_status()
            return response.json()

        await response.aclose()
        await asyncio.sleep(1)

    raise RuntimeError("user request failed")
```

Good:

```python
import httpx
from httpx_retries import Retry, RetryTransport


retry = Retry(
    total=3,
    backoff_factor=0.5,
    max_backoff_wait=2.0,
    status_forcelist={429, 502, 503, 504},
    allowed_methods={"GET", "HEAD", "OPTIONS"},
    respect_retry_after_header=True,
    backoff_jitter=1.0,
    total_timeout=10.0,
)
transport = RetryTransport(retry=retry)


async def create_client() -> httpx.AsyncClient:
    """Создать HTTPX client с управляемой retry-политикой."""
    return httpx.AsyncClient(
        base_url="https://partner.example",
        transport=transport,
        timeout=httpx.Timeout(connect=2.0, read=5.0, write=5.0, pool=1.0),
        trust_env=False,
    )
```

### HTTPX Transport Retries Treated As Full Retry Policy

Bad:

```python
import httpx


def create_partner_client() -> httpx.AsyncClient:
    """Создать HTTP client с ошибочным ожиданием retry по статусам."""
    # Плохо: AsyncHTTPTransport retries не повторяют ответы 429/502/503/504.
    transport = httpx.AsyncHTTPTransport(retries=3)
    return httpx.AsyncClient(
        base_url="https://partner.example",
        transport=transport,
    )
```

Good:

```python
import httpx
from httpx_retries import Retry, RetryTransport


def create_partner_transport() -> RetryTransport:
    """Создать transport с retry по HTTP-статусам и Retry-After."""
    retry = Retry(
        total=3,
        backoff_factor=0.5,
        max_backoff_wait=2.0,
        status_forcelist={429, 502, 503, 504},
        allowed_methods={"GET", "HEAD", "OPTIONS"},
        respect_retry_after_header=True,
        backoff_jitter=1.0,
        total_timeout=10.0,
    )
    base_transport = httpx.AsyncHTTPTransport(
        limits=httpx.Limits(max_connections=20, max_keepalive_connections=10),
    )
    return RetryTransport(transport=base_transport, retry=retry)
```

### Connection Limits Treated As Rate Limits

Bad:

```python
import httpx


def create_partner_client() -> httpx.AsyncClient:
    """Создать HTTP client с ошибочным ожиданием request-per-second лимита."""
    # Плохо: max_connections ограничивает пул соединений, а не квоту запросов в секунду.
    return httpx.AsyncClient(
        base_url="https://partner.example",
        limits=httpx.Limits(max_connections=5),
    )
```

Good:

```python
from typing import Protocol

import httpx


class RateLimiter(Protocol):
    """Интерфейс rate limiter, уже принятый в проекте."""

    async def acquire(self) -> None:
        """Дождаться доступного quota slot."""
        ...


class PartnerClient:
    """Клиент partner API с отдельными connection и request-rate лимитами."""

    def __init__(self, client: httpx.AsyncClient, rate_limiter: RateLimiter) -> None:
        self._client = client
        self._rate_limiter = rate_limiter

    async def load_user(self, user_id: str) -> dict:
        """Загрузить пользователя с соблюдением quota upstream API."""
        await self._rate_limiter.acquire()
        response = await self._client.get(f"/users/{user_id}")
        response.raise_for_status()
        return response.json()


def create_partner_client() -> httpx.AsyncClient:
    """Создать HTTP client с настройкой connection pool."""
    return httpx.AsyncClient(
        base_url="https://partner.example",
        limits=httpx.Limits(max_connections=20, max_keepalive_connections=10),
        timeout=httpx.Timeout(connect=2.0, read=5.0, write=5.0, pool=1.0),
        trust_env=False,
    )
```

### Blindly Retrying POST

Bad:

```python
import httpx
from httpx_retries import Retry, RetryTransport


retry = Retry(
    total=3,
    status_forcelist={429, 502, 503, 504},
    # Плохо: POST добавлен в retry без idempotency contract.
    allowed_methods={"GET", "POST"},
)
client = httpx.AsyncClient(transport=RetryTransport(retry=retry))


async def create_payment(payload: dict) -> dict:
    """Создать платеж во внешней системе."""
    response = await client.post("/payments", json=payload)
    response.raise_for_status()
    return response.json()
```

Good:

```python
import httpx
from httpx_retries import Retry, RetryTransport


retry = Retry(
    total=3,
    status_forcelist={429, 502, 503, 504},
    allowed_methods={"POST"},
    respect_retry_after_header=True,
    total_timeout=10.0,
)
client = httpx.AsyncClient(transport=RetryTransport(retry=retry))


async def create_payment(payload: dict, idempotency_key: str) -> dict:
    """Создать платеж с upstream idempotency key."""
    response = await client.post(
        "/payments",
        json=payload,
        headers={"Idempotency-Key": idempotency_key},
    )
    response.raise_for_status()
    return response.json()
```

### Retry-After Ignored After Retries Are Exhausted

Bad:

```python
import httpx
from httpx_retries import Retry, RetryTransport


retry = Retry(total=2, status_forcelist={429}, respect_retry_after_header=True)
client = httpx.AsyncClient(transport=RetryTransport(retry=retry))


async def load_profile(user_id: str) -> dict:
    """Загрузить профиль пользователя."""
    # Плохо: если после всех retry остался 429, он теряется как обычный HTTPStatusError.
    response = await client.get(f"/profiles/{user_id}")
    response.raise_for_status()
    return response.json()
```

Good:

```python
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime

import httpx
from httpx_retries import Retry, RetryTransport


class UpstreamRateLimitedError(RuntimeError):
    """Upstream API вернул rate-limit ответ после исчерпания retry."""

    def __init__(self, retry_after: float | None) -> None:
        super().__init__("upstream rate limit exceeded")
        self.retry_after = retry_after


def parse_retry_after(value: str | None, now: datetime) -> float | None:
    """Преобразовать Retry-After в задержку в секундах."""
    if value is None:
        return None

    try:
        delay = int(value)
    except ValueError:
        try:
            retry_at = parsedate_to_datetime(value)
        except (TypeError, ValueError):
            return None

        if retry_at.tzinfo is None:
            retry_at = retry_at.replace(tzinfo=UTC)

        return max(0.0, (retry_at - now).total_seconds())

    return max(0.0, float(delay))


retry = Retry(
    total=2,
    status_forcelist={429},
    allowed_methods={"GET"},
    respect_retry_after_header=True,
    max_backoff_wait=2.0,
    total_timeout=5.0,
)
client = httpx.AsyncClient(transport=RetryTransport(retry=retry))


async def load_profile(user_id: str) -> dict:
    """Загрузить профиль пользователя с явной обработкой финального 429."""
    response = await client.get(f"/profiles/{user_id}")

    if response.status_code == 429:
        retry_after = parse_retry_after(
            response.headers.get("Retry-After"),
            now=datetime.now(tz=UTC),
        )
        raise UpstreamRateLimitedError(retry_after=retry_after)

    response.raise_for_status()
    return response.json()
```

### Large Retry-After Without Total Timeout

Bad:

```python
import httpx
from httpx_retries import Retry, RetryTransport


retry = Retry(
    total=3,
    status_forcelist={429},
    respect_retry_after_header=True,
    # Плохо: нет total_timeout, а max_backoff_wait слишком велик для request path.
    max_backoff_wait=3600.0,
)
client = httpx.AsyncClient(transport=RetryTransport(retry=retry))
```

Good:

```python
import httpx
from httpx_retries import Retry, RetryTransport


retry = Retry(
    total=3,
    status_forcelist={429},
    allowed_methods={"GET", "HEAD", "OPTIONS"},
    respect_retry_after_header=True,
    backoff_factor=0.5,
    backoff_jitter=1.0,
    max_backoff_wait=2.0,
    total_timeout=5.0,
)
client = httpx.AsyncClient(
    transport=RetryTransport(retry=retry),
    timeout=httpx.Timeout(connect=2.0, read=5.0, write=5.0, pool=1.0),
)
```

### Unsafe User-Provided URL Fetch

Bad:

```python
import httpx


async def fetch_preview(url: str) -> bytes:
    """Скачать страницу для предпросмотра."""
    # Плохо: пользователь может указать внутренний адрес.
    async with httpx.AsyncClient() as client:
        response = await client.get(url)
        response.raise_for_status()
        return response.content
```

Good:

```python
from urllib.parse import urlparse

import httpx


ALLOWED_HOSTS = {"example.com", "cdn.example.com"}


def validate_external_url(url: str) -> str:
    """Проверить внешний URL по allowlist."""
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        raise ValueError("unsupported URL scheme")
    if parsed.hostname not in ALLOWED_HOSTS:
        raise ValueError("unsupported URL host")
    return url


async def fetch_preview(client: httpx.AsyncClient, url: str) -> bytes:
    """Скачать страницу только после проверки URL."""
    response = await client.get(validate_external_url(url), follow_redirects=False)
    response.raise_for_status()
    return response.content
```

### Leaking Authorization Header In Logs

Bad:

```python
import logging

import httpx


logger = logging.getLogger(__name__)


async def call_partner(client: httpx.AsyncClient, token: str) -> dict:
    """Вызвать partner API."""
    headers = {"Authorization": f"Bearer {token}"}
    logger.info("partner request headers=%s", headers)
    response = await client.get("/profile", headers=headers)
    response.raise_for_status()
    return response.json()
```

Good:

```python
import logging

import httpx


logger = logging.getLogger(__name__)


async def call_partner(client: httpx.AsyncClient, token: str) -> dict:
    """Вызвать partner API без утечки токена в лог."""
    headers = {"Authorization": f"Bearer {token}"}
    logger.info("partner request method=GET path=/profile")
    response = await client.get("/profile", headers=headers)
    response.raise_for_status()
    return response.json()
```

### Streaming Response Not Closed

Bad:

```python
import httpx


async def download_report(client: httpx.AsyncClient) -> bytes:
    """Скачать отчет потоком."""
    # Плохо: response не закрывается явно.
    response = await client.stream("GET", "/reports/current").__aenter__()
    return await response.aread()
```

Good:

```python
import httpx


async def download_report(client: httpx.AsyncClient, max_bytes: int) -> bytes:
    """Скачать отчет с ограничением размера."""
    chunks: list[bytes] = []
    received = 0

    async with client.stream("GET", "/reports/current") as response:
        response.raise_for_status()
        async for chunk in response.aiter_bytes():
            received += len(chunk)
            if received > max_bytes:
                raise ValueError("response is too large")
            chunks.append(chunk)

    return b"".join(chunks)
```

### External HTTP Call Inside DB Transaction

Bad:

```python
from sqlalchemy.ext.asyncio import AsyncSession


async def sync_customer(session: AsyncSession, customer_id: int, crm_client) -> None:
    """Синхронизировать клиента с внешней CRM."""
    async with session.begin():
        # Плохо: transaction удерживается во время сетевого вызова.
        customer_payload = await crm_client.get_customer(customer_id)
        await repository.update_customer(session, customer_id, customer_payload)
```

Good:

```python
from sqlalchemy.ext.asyncio import AsyncSession


async def sync_customer(session: AsyncSession, customer_id: int, crm_client) -> None:
    """Синхронизировать клиента короткой DB transaction."""
    customer_payload = await crm_client.get_customer(customer_id)

    async with session.begin():
        await repository.update_customer(session, customer_id, customer_payload)
```

### Implicit trust_env Behavior

Bad:

```python
import httpx


def create_partner_client() -> httpx.AsyncClient:
    """Создать HTTP client для partner API."""
    # Плохо: client неявно доверяет proxy/SSL переменным окружения.
    return httpx.AsyncClient(base_url="https://partner.example")
```

Good:

```python
import httpx


def create_partner_client() -> httpx.AsyncClient:
    """Создать HTTP client с явной политикой окружения."""
    return httpx.AsyncClient(
        base_url="https://partner.example",
        trust_env=False,
    )
```

## Review Checklist

- [ ] The client lifecycle is explicit and clients are closed.
- [ ] Hot-path code does not instantiate `AsyncClient` per call/request.
- [ ] Every call has explicit connect, read, write, and pool timeout policy.
- [ ] Shared clients have appropriate `httpx.Limits` for connection-pool control.
- [ ] Connection-pool limits are not treated as request-per-second or quota limits.
- [ ] Upstream request-per-second, per-minute, per-user, per-token, or quota limits are enforced through existing project mechanisms when required by the upstream contract.
- [ ] `httpx-retries` is used for ordinary HTTPX request/response retry policies.
- [ ] `httpx_retries.Retry` is configured explicitly for production integrations.
- [ ] Retry policy has explicit `allowed_methods`, `status_forcelist`, retryable exceptions, max attempts, max backoff, jitter, and `total_timeout` where they affect the contract.
- [ ] Retry policy is idempotency-aware; `POST` is retried only with an idempotency key, deduplication key, or documented upstream guarantee.
- [ ] `429` responses are handled explicitly and final `429` outcomes preserve safe `retry_after` metadata where useful.
- [ ] `Retry-After` handling is enabled through `respect_retry_after_header=True` when `429` or overload responses are retryable.
- [ ] Large `Retry-After` values cannot block request-handling paths beyond the configured `max_backoff_wait` and `total_timeout`.
- [ ] `RateLimit-*`, `X-RateLimit-*`, or vendor quota headers are parsed only when the upstream contract documents their semantics.
- [ ] HTTPX and `httpx-retries` outcomes are mapped to integration or domain errors at the boundary.
- [ ] Logs and exceptions avoid raw secrets, auth headers, cookies, and sensitive payloads.
- [ ] URLs are constructed with `base_url`, relative paths, `params`, `json`, `content`, or `files`.
- [ ] User-influenced URLs are scheme/host allowlisted and SSRF-protected.
- [ ] Redirect targets are re-validated when redirects are allowed.
- [ ] Streaming responses use `async with` and bounded reads where size matters.
- [ ] Routers do not contain HTTPX details; services call integration clients.
- [ ] External calls are outside DB write transactions.
- [ ] Unit tests use `MockTransport`; ASGI tests use `ASGITransport` when appropriate.
- [ ] Tests cover success parsing, timeout/network errors, non-2xx mapping, invalid JSON/schema, retries, rate-limit handling, headers, SSRF rejection, and streaming close behavior.
- [ ] Retry, backoff, and rate-limit tests avoid real sleeps and use deterministic fakes or documented library hooks where applicable.
- [ ] Cached external reads follow the project cashews rules instead of duplicating cache policy here.
- [ ] `trust_env` is explicitly configured for every shared integration client.
- [ ] Named client configuration cannot be silently reused with conflicting timeout, base URL, auth, limits, SSL, proxy, retry, rate-limit, or `trust_env` settings.
