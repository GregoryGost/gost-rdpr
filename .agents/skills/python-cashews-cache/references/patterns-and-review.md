# Python Cache Patterns And Review

Use this reference when designing or reviewing Python cache behavior.

## Decision Checklist

Add caching only when the repository shows:

- the operation is deterministic and read-oriented;
- bounded staleness is acceptable;
- the latency, cost, or frequency problem is clear;
- all inputs that affect the result are known;
- write paths that must refresh cached values are known;
- tests can cover repeated reads, refresh, and separate scopes.

If any answer is unknown, do not add caching yet.

## Placement

Preferred placement:

- service read methods returning DTOs or schemas;
- repository read projections returning scalar values, dictionaries, dataclasses, or DTOs.

Avoid caching routers by default. Avoid caching live ORM entities, sessions, connections, request objects, response objects, lazy loaders, or process-local runtime state.

## Good: Service-Level Read Cache

```python
from cashews import NOT_NONE, cache


class ProfileService:
    def __init__(self, repository: ProfileRepository) -> None:
        self.repository = repository

    @cache(
        ttl="5m",
        key="v1:tenant:{tenant_id}:profile:{profile_id}",
        tags=["tenant:{tenant_id}:profiles", "profile:{profile_id}"],
        condition=NOT_NONE,
        lock=True,
    )
    async def get_profile(self, tenant_id: str, profile_id: int) -> ProfileRead | None:
        profile = await self.repository.get_profile(tenant_id, profile_id)
        return ProfileRead.model_validate(profile) if profile else None
```

Why this is good:

- The cache is placed on a read-oriented service method.
- The key includes tenant and entity scope.
- The cached value is a detached read model.

## Bad: Route-Level Cache By Default

```python
from cashews import cache
from fastapi import APIRouter, Depends

router = APIRouter()


@router.get("/profiles/{profile_id}")
@cache(ttl="10m")
async def get_profile_route(
    profile_id: int,
    service: ProfileService = Depends(),
) -> ProfileRead:
    return await service.get_profile(profile_id)
```

Problems:

- The cache is attached to the HTTP boundary, not to a stable read model.
- Scope inputs such as tenant, role, locale, filters, or headers are easy to omit.
- The route hides cache behavior from service-level invalidation tests.

## Bad: Caching A Live Persistence Object

```python
from cashews import cache


class ProfileRepository:
    @cache(ttl="10m", key="v1:profile:{profile_id}")
    async def get_profile(self, profile_id: int) -> Profile:
        return await self.session.get(Profile, profile_id)
```

Problems:

- The value can be tied to a session lifecycle.
- Lazy relationships can behave incorrectly.
- Persistence models should not become cached API values.

## Naming, TTL, And Refresh

- Use explicit TTL.
- Use stable names based on business identifiers.
- Include result-shaping inputs such as tenant, user, filters, pagination, locale, feature flags, and schema version when relevant.
- Change schema version when the cached DTO shape changes.
- Refresh or remove cached values only after a successful write.
- Treat TTL as a fallback, not as the main consistency strategy for mutable data.

## Good: Scoped Key For User-Visible Data

```python
from cashews import cache


class ProfileSearchService:
    @cache(
        ttl="2m",
        key="v1:tenant:{tenant_id}:role:{role}:profiles:q:{query}:page:{page}:size:{size}",
        tags=["tenant:{tenant_id}:profiles"],
    )
    async def search_profiles(
        self,
        tenant_id: str,
        role: str,
        query: str,
        page: int,
        size: int,
    ) -> ProfilePage:
        return await self.repository.search_profiles(
            tenant_id=tenant_id,
            role=role,
            query=query,
            page=page,
            size=size,
        )
```

Why this is good:

- Tenant and role are part of the key.
- Pagination and query inputs are part of the key.
- The tag represents the aggregate invalidation scope.

## Bad: Key Missing Scope

```python
from cashews import cache


class ProfileSearchService:
    @cache(ttl="2m", key="v1:profiles:q:{query}")
    async def search_profiles(
        self,
        tenant_id: str,
        role: str,
        query: str,
    ) -> list[ProfileRead]:
        return await self.repository.search_profiles(tenant_id, role, query)
```

Problems:

- Different tenants can collide.
- Different roles can collide.
- Pagination, locale, or feature flags can be forgotten as the method grows.

## Good: Explicit Key For Class Method

```python
from cashews import cache


class PricingService:
    @cache(ttl="1m", key="v1:tenant:{tenant_id}:product:{product_id}:price")
    async def get_price(self, tenant_id: str, product_id: int) -> PriceRead:
        price = await self.repository.get_price(tenant_id, product_id)
        return PriceRead.model_validate(price)
```

Why this is good:

- The key uses business inputs only.
- Object identity is not part of the cache key.

## Bad: Implicit Method Key

```python
from cashews import cache


class PricingService:
    @cache(ttl="1m")
    async def get_price(self, product_id: int) -> PriceRead:
        price = await self.repository.get_price(product_id)
        return PriceRead.model_validate(price)
```

Problem: implicit method-key generation can include instance details or omit business scope that should be explicit.

## Good: Refresh After Write

```python
from cashews import cache


class ProfileService:
    async def update_profile(self, tenant_id: str, profile_id: int, data: ProfileUpdate) -> ProfileRead:
        async with self.unit_of_work.transaction():
            profile = await self.repository.update_profile(tenant_id, profile_id, data)
            result = ProfileRead.model_validate(profile)

        await cache.delete_tags(f"profile:{profile_id}")
        await cache.delete_tags(f"tenant:{tenant_id}:profiles")
        return result
```

Why this is good:

- Cache refresh happens after the write transaction has completed.
- Entity and aggregate scopes are both covered.

## Bad: Refresh Before The Transaction Outcome Is Known

```python
from cashews import cache


async def update_profile_bad(profile_id: int, data: ProfileUpdate) -> None:
    async with session.begin():
        await repository.update_profile(profile_id, data)
        await cache.delete_tags(f"profile:{profile_id}")
```

Problem: if the transaction rolls back later, the cache no longer reflects committed state.

## Bad: Broad Wildcard Deletion In Request Path

```python
from cashews import cache


async def update_profile_bad(profile_id: int, data: ProfileUpdate) -> None:
    await repository.update_profile(profile_id, data)
    await cache.delete_match("v1:profiles:*")
```

Problems:

- Wildcard deletion can scan a large keyspace.
- It can affect unrelated cached values.
- It hides the actual invalidation domain.

## Negative Caching

Use negative caching only when repeated missing reads are an observed problem.

```python
from cashews import cache


class ProfileService:
    @cache(ttl="20s", key="v1:profile-missing:{profile_id}")
    async def profile_exists(self, profile_id: int) -> bool:
        return await self.repository.profile_exists(profile_id)
```

Why this can be acceptable:

- The TTL is short.
- The value is a boolean, not a missing object payload.
- The behavior is explicit and easy to test.

## FastAPI Integration

When FastAPI is active:

- configure shared cache resources in application lifespan or the project resource manager;
- close cache resources during shutdown when required by the library;
- keep HTTP handlers thin;
- prefer service-level data caching for business endpoints;
- use HTTP cache middleware only when HTTP cache semantics are part of the task.

```python
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from cashews import cache
from fastapi import FastAPI


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    cache.setup(settings.CACHE_DSN, suppress=False)
    try:
        yield
    finally:
        await cache.close()


app = FastAPI(lifespan=lifespan)
```

## FastAPI Good: Route Delegates To Scoped Cached Service

```python
from fastapi import APIRouter, Depends, Query

router = APIRouter()


@router.get("/profiles")
async def list_profiles(
    query: str = Query(default=""),
    page: int = Query(default=1, ge=1),
    size: int = Query(default=50, ge=1, le=100),
    principal: Principal = Depends(require_principal),
    service: ProfileSearchService = Depends(get_profile_search_service),
) -> ProfilePage:
    return await service.search_profiles(
        tenant_id=principal.tenant_id,
        role=principal.role,
        query=query,
        page=page,
        size=size,
    )
```

Why this is good:

- The route resolves HTTP and auth context.
- The service owns cache policy.
- Tenant, role, query, and pagination reach the cached method as explicit arguments.

## FastAPI Bad: Hidden Tenant Scope From Context

```python
from cashews import cache


class ProfileSearchService:
    @cache(ttl="2m", key="v1:profiles:q:{query}")
    async def search_profiles(self, query: str) -> ProfilePage:
        tenant_id = current_tenant_id.get()
        return await self.repository.search_profiles(tenant_id, query)
```

Problems:

- The tenant affects the result but is absent from the key.
- Hidden context makes cache behavior hard to test.
- Different tenants can receive the same cached result.

## FastAPI Bad: Caching Request Or Response Objects

```python
from cashews import cache
from fastapi import Request, Response


class AuditService:
    @cache(ttl="1m", key="v1:audit:{request.url.path}")
    async def audit_summary(self, request: Request, response: Response) -> AuditSummary:
        return await self.repository.audit_summary(request.headers, response.status_code)
```

Problems:

- `Request` and `Response` are runtime HTTP objects, not stable cache inputs.
- Headers can include sensitive values or high-cardinality data.
- Response status can depend on work that should not be part of a read cache key.

## FastAPI Good: Extract Stable HTTP Inputs Before Cached Call

```python
from fastapi import Header


@router.get("/reports/{report_id}")
async def get_report(
    report_id: int,
    accept_language: str = Header(default="en"),
    principal: Principal = Depends(require_principal),
    service: ReportService = Depends(get_report_service),
) -> ReportRead:
    locale = normalize_locale(accept_language)
    return await service.get_report(
        tenant_id=principal.tenant_id,
        user_id=principal.user_id,
        report_id=report_id,
        locale=locale,
    )
```

Why this is good:

- The route extracts and normalizes HTTP details.
- The cached service can include stable locale and user scope in the key.
- Raw headers do not enter the cache key.

## FastAPI Bad: Authenticated Response Cache Without Scope

```python
from cashews import cache


class ReportService:
    @cache(ttl="10m", key="v1:report:{report_id}")
    async def get_report(self, user_id: int, report_id: int) -> ReportRead:
        return await self.repository.get_report_for_user(user_id, report_id)
```

Problems:

- User permissions affect the result.
- The key ignores `user_id`.
- A report view for one user can be served to another.

## FastAPI Good: Public HTTP Cache Case

```python
from fastapi import APIRouter, Response

router = APIRouter()


@router.get("/public/catalog")
async def public_catalog(response: Response, service: CatalogService = Depends(get_catalog_service)) -> CatalogRead:
    response.headers["Cache-Control"] = "public, max-age=60"
    return await service.get_public_catalog()
```

Why this can be acceptable:

- The endpoint is public and does not depend on user permissions.
- HTTP cache semantics are explicit in headers.
- Server-side data caching can still live in the service if needed.

## FastAPI Bad: HTTP Cache Header On User-Specific Endpoint

```python
@router.get("/me")
async def me(response: Response, principal: Principal = Depends(require_principal)) -> UserRead:
    response.headers["Cache-Control"] = "public, max-age=300"
    return principal.user
```

Problem: user-specific data must not be marked as public shared-cache content.

## FastAPI Bad: Cache Setup At Module Import

```python
from cashews import cache

cache.setup("redis://localhost:6379/0")

app = FastAPI()
```

Problems:

- Resource setup happens during import.
- Tests cannot easily isolate configuration.
- Shutdown ownership is unclear.
- The DSN is hardcoded outside settings.

## FastAPI Good: Dependency Uses Already-Owned Cache Resources

```python
from cashews import cache
from fastapi import Depends


def get_profile_service(repository: ProfileRepository = Depends(get_profile_repository)) -> ProfileService:
    return ProfileService(repository=repository, cache=cache)
```

Why this can be good:

- The cache resource is configured by the app lifecycle.
- The dependency only wires services.
- Tests can override the dependency or configure an isolated backend.

## Testing

- Use an isolated backend for tests.
- Clear cache state between test cases when needed.
- Test repeated reads.
- Test refresh after create, update, or delete.
- Test separate scopes for different users, tenants, filters, or pagination.

## Good: Hit/Miss Test

```python
async def test_profile_read_uses_cache(
    profile_service: ProfileService,
    repository: ProfileRepository,
) -> None:
    await profile_service.get_profile("tenant-a", 10)
    await profile_service.get_profile("tenant-a", 10)

    assert repository.get_profile_calls == 1
```

## Good: Scope Separation Test

```python
async def test_profile_cache_is_scoped_by_tenant(
    profile_service: ProfileService,
    repository: ProfileRepository,
) -> None:
    await profile_service.get_profile("tenant-a", 10)
    await profile_service.get_profile("tenant-b", 10)

    assert repository.get_profile_calls == 2
```

## Good: Invalidation Test

```python
async def test_profile_update_refreshes_cache(
    profile_service: ProfileService,
    repository: ProfileRepository,
) -> None:
    await profile_service.get_profile("tenant-a", 10)
    await profile_service.update_profile("tenant-a", 10, ProfileUpdate(name="new"))
    await profile_service.get_profile("tenant-a", 10)

    assert repository.get_profile_calls == 2
```

## FastAPI Good: Endpoint Test Keeps Cache Scope Visible

```python
async def test_profile_endpoint_cache_is_tenant_scoped(
    client: AsyncClient,
    repository: ProfileRepository,
) -> None:
    await client.get("/profiles/10", headers={"X-Tenant-ID": "tenant-a"})
    await client.get("/profiles/10", headers={"X-Tenant-ID": "tenant-b"})

    assert repository.get_profile_calls == 2
```

Why this is useful:

- The test crosses the FastAPI boundary.
- It verifies that dependency-derived tenant scope reaches cache key inputs.
- It catches accidental route-level or hidden-context caching.

## FastAPI Good: Lifespan Test Uses Isolated Backend

```python
from cashews import cache


async def test_cache_backend_is_isolated(app: FastAPI) -> None:
    cache.setup("mem://")
    try:
        await cache.set("test-key", "value", expire="1m")
        assert await cache.get("test-key") == "value"
    finally:
        await cache.clear()
        await cache.close()
```

Why this is useful:

- The test does not reuse production cache state.
- Cleanup is explicit.
- The resource lifecycle is visible.

## Review Questions

- What problem does caching solve?
- Is stale data acceptable?
- Which inputs affect result shape or visibility?
- Which writes refresh cached values?
- Are cached values detached from live resources?
- Is test isolation explicit?
- If FastAPI is active, are dependency-derived tenant/user/role values explicit cache inputs?
- If HTTP cache headers or middleware are used, are the responses public and safe for shared caches?
