# GOST RDPR (Resolve Domains Per Record)

GOST RDPR resolves domain names, imports domain and IP lists, and synchronizes stored addresses with
MikroTik RouterOS firewall address lists and routing tables.

- [Backend source](https://github.com/GregoryGost/gost-rdpr)
- [Docker images](https://hub.docker.com/r/gregorygost/gost-rdpr): `latest`, `dev` and version tags
- [Web UI source](https://github.com/GregoryGost/gost-rdpr-ui)

The Docker image includes the Python API and web UI. Supported image platforms are `linux/amd64` and `linux/arm64`.
The RouterOS integration requires **RouterOS 7.9 or later** because the current client uses the HTTP REST API.

## Contents

- [Quick start](#quick-start)
- [Using the application](#using-the-application)
- [Configuration](#configuration)
- [Operation and data safety](#operation-and-data-safety)
- [MikroTik RouterOS](#mikrotik-routeros)
- [Development](#development)
- [License and author](#license-and-author)

## Quick start

Install Docker with Linux container support. Run the following commands in PowerShell:

```powershell
docker volume create gost-rdpr-db
docker run -d --name gost-rdpr --restart unless-stopped --stop-timeout 60 `
  -p 127.0.0.1:8080:80 -p 127.0.0.1:5000:4000 `
  --mount type=volume,source=gost-rdpr-db,target=/app/db `
  -e ROOT_LOG_LEVEL=error -e APP_LOG_LEVEL=error `
  gregorygost/gost-rdpr:latest
```

The named volume keeps the database when the container is replaced. Reuse `gost-rdpr-db` on subsequent deployments.
Use a published version tag instead of `latest` when you need a fixed application version.
The multiline examples use PowerShell continuation characters; adapt those characters for other host shells.
See the [Docker run reference](https://docs.docker.com/reference/cli/docker/container/run/) for these options.

The example binds both ports to localhost. To allow access from another machine, replace `127.0.0.1` with the intended
host LAN address and configure network access for that deployment.

### Application addresses

| Purpose | Address with the example above |
| --- | --- |
| Web UI | `http://localhost:8080/` |
| API through Nginx | `http://localhost:8080/api/` |
| Health check | `http://localhost:8080/api/health` |
| Prometheus metrics | `http://localhost:8080/api/metrics` |
| Direct backend API | `http://localhost:5000/` |
| Swagger UI | `http://localhost:5000/docs` |
| OpenAPI JSON | `http://localhost:5000/docs/openapi.json` |

Nginx listens on container port `80` and forwards `/api/` to backend port `4000`, removing the `/api` prefix.
Use the direct backend address for Swagger UI. The checked-in [OpenAPI export](./docs/OPENAPI.json) is also available.

Inspect container status and logs:

```powershell
docker ps --filter name=gost-rdpr
docker logs --tail 100 gost-rdpr
```

## Using the application

Use the web UI or Swagger UI to configure and run the application:

1. Configure ordinary DNS servers or DoH endpoints. When no custom servers are selected, the default DNS row is used.
1. Add individual domains, domain-list sources or IP-list sources, then run the corresponding import commands.
1. Resolve new domains or refresh stale domains and inspect the resulting stored addresses.
1. Add a RouterOS connection with a dedicated managed list/table name, then request synchronization.

The main commands are available under the API base address shown above:

| Action | Method and path |
| --- | --- |
| Import domain and IP lists | `POST /commands/lists/load` |
| Resolve new domains | `POST /commands/domains/resolve/new` |
| Refresh stale domains | `POST /commands/domains/resolve/stale` |
| Synchronize RouterOS IPv4 addresses | `POST /commands/ros/update?type=4` |

An accepted background command is not a confirmation that its results have been committed.
Wait for persistence results and read the stored records before relying on an update.
See [Operation and data safety](#operation-and-data-safety) for resolution and shutdown behavior.

<table>
  <tr>
    <td width="50%">
      <img src="docs/screenshots/dashboard-dark.png" alt="Dashboard home page" />
      <p align="center"><i>Dashboard</i></p>
    </td>
    <td width="50%">
      <img src="docs/screenshots/domains-page-dark.png" alt="Domain management page" />
      <p align="center"><i>Domains</i></p>
    </td>
  </tr>
</table>

## Configuration

Set environment variables when creating the container, for example `-e ROOT_LOG_LEVEL=info`.
Local source runs also load `.env` from the working directory. Restart the application after changing these settings.
DNS servers, list sources and RouterOS connections are managed through the UI/API and stored in SQLite.

The tables describe defaults in [config/config.py](./config/config.py).
Durations are in seconds unless stated otherwise.
For optional timeout overrides, omit the variable to inherit its fallback; `None` below means no explicit override.
The application version is read from [pyproject.toml](./pyproject.toml).
`APP_VERSION` is not an environment setting.

### Application and logging

| Variable | Type | Default | Description |
| --- | --- | --- | --- |
| `ROOT_PATH` | str | `normpath(getcwd())` | Path to the application root folder |
| `ROOT_LOG_LEVEL` | str | `error` | Root level logging |
| `APP_TITLE` | str | `GOST-RDPR (Resolve Domains Per Records)` | Application name |
| `APP_SUMMARY` | str | `A utility for working with Mikrotik RouterOS and BGP protocol for announcing IP addresses` | Description title |
| `APP_DESCRIPTION` | str | `The utility provides parsing of domain names into IP addresses, processing of domain lists and their subsequent parsing, processing of individual IP addresses and summarized IP groups. Updates firewall address list and routing table` | Detailed description of the application |
| `APP_DEBUG` | bool | `False` | FastAPI debug mode |
| `APP_HOST` | str | `0.0.0.0` | Listen on IP addr. `0.0.0.0` - Listen on all IP addresses |
| `APP_PORT` | int | `4000` | Listen on TCP/IP specific port |
| `APP_LOG_LEVEL` | str | `error` | Application level logging |
| `REQ_DEFAULT_LIMIT` | int | `100` | Maximum number of records returned by a paginated API request |

In the stock image, keep `APP_PORT=4000`: the bundled Nginx configuration targets that port.
`ROOT_LOG_LEVEL` controls the application logger; `APP_LOG_LEVEL` controls Uvicorn logging.

### Domains and lists

| Variable | Type | Default | Description |
| --- | --- | --- | --- |
| `DOMAINS_FILTERED_MIN_LEN` | int | `3` | The minimum domain length required to save it to the database. This is necessary to filter out empty domains that, for some reason, are generated in MikroTik scripts |
| `DOMAINS_UPDATE_INTERVAL` | int | `172800` | Seconds after a complete resolution checkpoint before automatic stale eligibility; explicit saved-ID requests bypass this interval |
| `DOMAINS_RESOLVE_WORKER_LIMIT` | int | `32` | Positive shared maximum of saving domain operations in DNS, preparation or writer admission across new, stale and explicit requests |
| `DOMAINS_RESOLVE_SEMAPHORE_LIMIT` | int | `64` | Positive shared limit of concurrent classic DNS and DoH A/CNAME operations, including single-domain checks |
| `DOMAINS_RESOLVE_NEW_BATCH_SIZE` | int | `500` | Legacy setting retained for configuration compatibility; automatic NEW scans now select their complete finite membership |
| `DOMAINS_RESOLVE_STALE_BATCH_SIZE` | int | `2000` | Legacy setting retained for configuration compatibility; automatic STALE scans now select their complete finite membership |
| `DOMAINS_BLACK_LIST` | str | empty string | Comma-separated domains excluded from storage |
| `LISTS_UPDATE_INTERVAL_SEC` | int | `604800` | The period after which the file must be uploaded and verified again. Specified in seconds. 604800s = 7days |
| `ATTEMPTS_LIMIT` | int | `5` | How many times a file must be checked with a negative result before it (and all its child entities) are deleted from the database |

| Variable | Type | Default | Description |
| --- | --- | --- | --- |
| `IP_NOT_ALLOWED` | str | `0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.0.2.0/24, 192.88.99.0/24, 192.168.0.0/16, 198.18.0.0/15, 198.51.100.0/24, 203.0.113.0/24, 224.0.0.0/4, 240.0.0.0/4, ::/128, ::1/128, fc00::/7, fe80::/10, ff00::/8, 2001:db8::/32` | Comma-separated CIDR networks that must not be saved in the database. |

The legacy NEW/STALE batch-size settings no longer limit the total domains in an automatic pass.
Use the worker and semaphore limits to control concurrency, and `DOMAINS_UPDATE_INTERVAL` to control stale eligibility.

### Queues and database

| Variable | Type | Default | Description |
| --- | --- | --- | --- |
| `QUEUE_MAX_SIZE` | int | `10000` | Positive capacity of each writer and RouterOS queue, and maximum accepted, unstarted explicit domain operations; producers wait when full |
| `QUEUE_GET_TIMEOUT` | float | `0.1` | Maximum waiting time for a queue entry. 0.1s = 100ms |
| `QUEUE_SLEEP_TIMEOUT` | float | `0.01` | The maximum wait time while the queue is empty. At the same time, the infinite loop should allow the scheduler to integrate other tasks into the overall flow. 0.01s = 10ms |
| `RESOLVE_DOMAINS_LOG_EVERY` | int | `10` | Maximum intermediate INFO progress messages per nonempty NEW/STALE pass; minimum `3`. Initial totals and final summaries are excluded |

Progress reports completed processing of the selected domains, including work shared with another operation.
An empty pass emits only `Нет доменов для обработки`. Processing and persistence have separate INFO summaries;
processing completion does not wait for database commits. Per-batch persistence details are available at DEBUG.

| Variable | Type | Default | Description |
| --- | --- | --- | --- |
| `DB_LOG_LEVEL` | str | `error` | SQLAlchemy level logging |
| `DB_TIMEOUT` | float | `30.0` | Maximum time to wait for a database to be freed |
| `DB_BASE_DIR` | str | `db` | Directory containing the SQLite database; mounted at `/app/db` in the example image |
| `DB_FILE_NAME` | str | `rdpr-db.sqlite` | Database file name |
| `DB_TABLE_PREFIX` | str | `rdpr_` | Prefix for database table names |
| `DB_SAVE_BATCH_SIZE` | int | `1000` | Maximum queued commands in one writer transaction; independent of domain scan membership and IP row count |
| `DB_SAVE_BATCH_TIMEOUT` | float | `0.1` | Maximum idle time in seconds between commands received by the writer from its queue; each received command restarts the timer |
| `DB_SHUTDOWN_TIMEOUT` | float | `20.0` | Time in seconds to wait for the database writer during shutdown. Expiry reports unresolved writes; it does not imply a successful drain |
| `DB_TUNE_JOURNAL_MODE` | str | `WAL` | SQLite journal mode: `WAL`, `DELETE`, `TRUNCATE`, `PERSIST` or `MEMORY`. `OFF` is rejected because transactions require rollback support |
| `DB_TUNE_WAL_AUTOCHECKPOINT` | int | `1000` | Initiate a checkpoint approximately every 1000 WAL pages (choose experimentally: if WAL grows too quickly, decrease it; if checkpoints interfere, increase it) |
| `DB_TUNE_SYNCHRONOUS` | str | `NORMAL` | SQLite synchronization policy; `FULL` increases durability at additional I/O cost |
| `DB_TUNE_TEMP_STORE` | str | `FILE` | Defines where SQLite stores temporary tables and indexes. `MEMORY` can improve performance but increases memory consumption |
| `DB_TUNE_MMAP_SIZE` | int | `0` | Maximum database file memory mapping in bytes. `0` disables mapping; a negative value restores the SQLite build default. The effective size may be capped by SQLite or the platform |
| `DB_TUNE_CACHE_SIZE` | int | `-2048` | If the value is negative, SQLite treats it as kibibytes; `-2048` means about 2 MiB cache. Positive values are interpreted as number of database pages. Lower values reduce RAM usage; higher values may improve performance at the cost of memory |
| `DB_TUNE_BUSY_TIMEOUT` | int | `2000` | This is the timeout (in milliseconds) during which SQLite will retry acquiring a lock instead of immediately failing with a "database is locked" error. Defaults in SQLite to 0 (no wait). |
| `DB_POOL_SIZE` | int | `5` | The number of connections to keep open inside the read connection pool |
| `DB_POOL_RECYCLE` | int | `1500` | This setting causes the pool to recycle connections after the given number of seconds has passed |
| `DB_POOL_TIMEOUT` | int | `30` | Number of seconds to wait before giving up on getting a connection from the pool |
| `DB_POOL_SIZE_OVERFLOW` | int | `0` | Maximum additional read connections above `DB_POOL_SIZE` |

Keep the database directory aligned with the volume mount when changing `DB_BASE_DIR`.
`DB_SAVE_BATCH_SIZE` counts queued commands, not domains selected for a scan or individual IP rows.
`DB_SAVE_BATCH_TIMEOUT` is an idle collection timeout: each received command restarts it.
Continuous arrivals can delay a partial batch until it reaches the size limit.

### Outbound HTTP

| Variable | Type | Default | Description |
| --- | --- | --- | --- |
| `HTTPX_LOG_LEVEL` | str | `error` | HTTPX logging level |
| `REQ_CONNECTION_RETRIES` | int | `3` | Maximum additional attempts through `httpx-retries`, subject to the named client's method, status, exception and retry-sleep policy |
| `REQ_RETRY_BACKOFF_FACTOR` | float | `0.25` | Exponential retry-backoff factor in seconds |
| `REQ_RETRY_BACKOFF_JITTER` | float | `1.0` | Retry-backoff jitter fraction, between zero and one |
| `REQ_RETRY_MAX_BACKOFF_WAIT` | float | `2.0` | Maximum delay for one retry, including `Retry-After` |
| `REQ_RETRY_TOTAL_TIMEOUT` | float | `5.0` | Maximum cumulative retry sleep; excludes network I/O and pool waiting |
| `REQ_TIMEOUT_DEFAULT` | float | `20.0` | Fallback for HTTP write and pool timeouts |
| `REQ_TIMEOUT_CONNECT` | float | `20.0` | Individual timeout for `connect` |
| `REQ_TIMEOUT_READ` | float | `30.0` | Individual timeout for `read` |
| `REQ_TIMEOUT_WRITE` | float or null | `None` | HTTP write timeout; unset values inherit `REQ_TIMEOUT_DEFAULT` |
| `REQ_TIMEOUT_POOL` | float or null | `None` | Pool-slot acquisition timeout; unset values inherit `REQ_TIMEOUT_DEFAULT` |
| `REQ_MAX_CONNECTIONS` | int | `32` | Maximum open connections in each named client's transport pool |
| `REQ_MAX_KEEPALIVE_CONNECTIONS` | int | `32` | Maximum idle connections per named pool, capped by `REQ_MAX_CONNECTIONS` |
| `REQ_SSL_VERIFY` | bool | `True` | Verify HTTPS server certificates |

Connection limits apply to each named HTTP pool independently and are not request-rate limits.
General connect/read/write/pool defaults are `20/30/20/20` seconds.
Retries apply only to selected methods, HTTP statuses and transport failures.
`REQ_RETRY_TOTAL_TIMEOUT` limits cumulative retry sleep, excluding network I/O and pool waiting.
Environment certificate configuration is supported; environment proxy settings are not used.

### DNS and DoH

| Variable | Type | Default | Description |
| --- | --- | --- | --- |
| `DNS_TIMEOUT` | float | `2.0` | Time in seconds for one ordinary DNS server response |
| `DNS_LIFETIME` | float | `5.0` | Total ordinary DNS resolution lifetime, including its internal attempts |
| `DNS_OPERATION_TIMEOUT` | float | `10.0` | Total budget for one ordinary A or CNAME operation, including semaphore admission |
| `DOH_TIMEOUT_CONNECT` | float | `3.0` | DoH connect timeout |
| `DOH_TIMEOUT_READ` | float | `5.0` | DoH timeout for an individual response read |
| `DOH_TIMEOUT_WRITE` | float | `3.0` | DoH write timeout |
| `DOH_TIMEOUT_POOL` | float | `2.0` | DoH connection-pool acquisition timeout |
| `DOH_CONNECTION_RETRIES` | int | `1` | Maximum additional DoH HTTP attempts within the operation budget |
| `DOH_RETRY_TOTAL_TIMEOUT` | float | `1.0` | Maximum cumulative DoH retry sleep |
| `DOH_OPERATION_TIMEOUT` | float | `10.0` | Total budget for one DoH A or CNAME operation, including semaphore, pool, retry and response-body waits |

DNS and DoH operation budgets apply to each A or CNAME query, including semaphore admission.
They are not deadlines for an entire domain or job. Duration settings must be positive and finite.
DoH uses its own retry count and sleep budget instead of the general HTTP values.

### RIPEstat

| Variable | Type | Default | Description |
| --- | --- | --- | --- |
| `RIPE_STAT_BASE_URL` | str | `https://stat.ripe.net` | RIPEstat API base URL for IPv4 prefix lookups |
| `RIPE_STAT_TIMEOUT_CONNECT` | float | `3.0` | RIPEstat connect timeout |
| `RIPE_STAT_TIMEOUT_READ` | float | `5.0` | RIPEstat timeout for an individual response read |
| `RIPE_STAT_TIMEOUT_WRITE` | float | `3.0` | RIPEstat write timeout |
| `RIPE_STAT_TIMEOUT_POOL` | float | `2.0` | RIPEstat connection-pool acquisition timeout |
| `RIPE_STAT_CONNECTION_RETRIES` | int | `1` | Maximum additional RIPEstat HTTP attempts within the lookup budget |
| `RIPE_STAT_RETRY_TOTAL_TIMEOUT` | float | `1.0` | Maximum cumulative RIPEstat retry sleep |
| `RIPE_STAT_OPERATION_TIMEOUT` | float | `10.0` | Total budget for one prefix lookup, including cache, cache-lock, retry and response-body waits; resolver lookups also include semaphore admission |
| `RIPE_STAT_REQUESTS_SEMAPHORE_LIMIT` | int | `16` | Maximum number of concurrent RIPEstat prefix lookups during domain resolving |
| `RIPE_STAT_CACHE_SIZE` | int | `10000` | Maximum number of RIPEstat prefix records in the in-memory cache |
| `RIPE_STAT_PREFIX_CACHE_TTL_SEC` | int | `28800` | TTL in seconds for a RIPEstat result with a prefix |
| `RIPE_STAT_EMPTY_PREFIX_CACHE_TTL_SEC` | int | `3600` | TTL in seconds for a RIPEstat result without a prefix |
| `RIPE_STAT_CACHE_LOCK_TTL_SEC` | int | `120` | Maximum lifetime in seconds of a per-IP RIPEstat cache lock |

RIPEstat caches IPv4 prefix results in process-local memory. Successful empty results have their own TTL;
errors and expired lookups are not cached as successful empty responses.
A failed lookup retains a matching stored CIDR when available, otherwise the host address.

### RouterOS HTTP timeouts

| Variable | Type | Default | Description |
| --- | --- | --- | --- |
| `ROS_REST_API_READ_TIMEOUT` | float | `59.0` | RouterOS response-read timeout; below its 60-second command limit |
| `ROS_REST_API_DEFAULT_TIMEOUT` | float | `59.0` | Default timeout for RouterOS REST API requests |
| `ROS_REST_API_WRITE_TIMEOUT` | float or null | `None` | RouterOS write timeout; unset values inherit `ROS_REST_API_DEFAULT_TIMEOUT` |
| `ROS_REST_API_POOL_TIMEOUT` | float or null | `None` | RouterOS pool-slot timeout; unset values inherit `ROS_REST_API_DEFAULT_TIMEOUT` |

RouterOS connect/read/write/pool defaults are `20/59/59/59` seconds.
Creation requests (`PUT`) are sent once; eligible reads, fixed-value updates and deletions can be retried.

## Operation and data safety

### DNS results and shared addresses

Addresses from configured DNS endpoints are combined before storage.
A complete trustworthy IPv4 result replaces that domain's previous IPv4 support and advances its refresh checkpoint.
Confirmed absence can remove old addresses. Partial results only add reliable positive evidence.
Timeouts, connection failures, SERVFAIL and invalid responses preserve previous evidence and cannot prove disappearance.
IPv4 reconciliation leaves existing IPv6 records untouched.

An exact IP address or CIDR has one global record and can be supported by multiple domains or IP lists.
Removing one domain's support does not remove another domain's address; an IP-list refresh withdraws only that list's
support. Explicit `/ips` deletion removes the global record and all its support.
Manually assigning an address to a positive domain ID includes it in that domain's DNS reconciliation.
Domain ID `0` represents standalone ownership.

Each automatic job uses one DNS configuration snapshot. Changes committed after that read apply to the next job;
single-domain operations read committed settings when they start. DNS response caching is disabled.

### Concurrency and persistence

Run **one application process per database**. The writer queue, job coordination and caches are process-local.
Saving operations share the domain worker pool; DNS/DoH and RIPEstat have separate concurrency limits.
New domains and explicit saved-ID requests take priority over subsequent stale dispatch.
Already started stale work finishes; continuous new demand can postpone stale processing.
Repeated mass triggers can coalesce. Automatic passes capture finite membership, with metadata memory growing with
the number of selected domains; the worker limit does not make the whole pass constant-memory.

Runtime writes go through one bounded memory queue. Queue admission and processing completion do not establish commit
or immediate visibility to reads. A full queue makes producers wait. The writer commits batches in transactions;
ambiguous commit outcomes are retained as unknown and are not automatically replayed.
Pending queue contents cannot be recovered after a crash or forced termination.

### Shutdown, backups and updates

Allow time for graceful shutdown before replacing the container. The quick-start example gives Docker 60 seconds;
the database writer has a separate default 20-second shutdown budget, and Supervisor allows the Python process
30 seconds. Raising `DB_SHUTDOWN_TIMEOUT` alone does not extend either outer deadline.
A timeout or unresolved-write error does not confirm a successful drain.

For an offline backup, stop the container, inspect its shutdown logs, then copy the entire database directory to a
fresh backup destination before restarting:

```powershell
docker stop gost-rdpr
docker logs --tail 100 gost-rdpr
docker cp gost-rdpr:/app/db ./gost-rdpr-backup
docker start gost-rdpr
```

Retain any SQLite sidecar files with the database directory; copying only the main file while the application runs
is not an offline backup. The database also contains RouterOS connection credentials, so protect its backups.

Before an update, back up the database and retain the previous image version. Recreate the container using the chosen
image tag, the same volume and the required environment/port options. Startup applies pending migrations.
Running an older application against an upgraded database is unsupported; restore the matching previous database
and application together when reverting.

### Monitoring

Scrape `/api/metrics` through Nginx, or `/metrics` on the direct backend port.

| Metric family | Use |
| --- | --- |
| `httpx_requests_total`, `httpx_responses_total`, `httpx_exchange_duration_seconds` | Outbound HTTP activity and exchange latency |
| `resolution_dns_duration_seconds`, `resolution_dns_semaphore_wait_seconds` | DNS outcomes, durations and admission waits |
| `resolution_ripe_duration_seconds` | RIPEstat cache, lock and network phases |
| `resolution_queue_duration_seconds`, `resolution_writer_duration_seconds` | Writer backlog, transaction and commit timing |
| `resolution_run_events_total`, `resolution_run_elapsed_seconds`, `resolution_run_snapshot` | Processing results and persistence outcomes for new, stale and explicit resolution |

Processing counts and rates describe attempts. Persistence outcomes distinguish admitted, pending, confirmed,
known-not-committed and unknown commands; confirmed commands are not counts of inserted IP rows.
Compare processing with confirmed persistence and failures. Durations are in seconds, nested phases overlap,
and histogram quantiles are estimates. These metrics are process-local and do not establish crash durability.

## MikroTik RouterOS

### Connect an existing router

The current client constructs `http://<host>/rest/...` URLs and uses HTTP Basic authentication.
Configure RouterOS 7.9 or later with the `www` service and HTTP REST access enabled.
Keep this connection on a trusted management network or inside a VPN because HTTP does not encrypt credentials.
The [RouterOS REST API guide](https://manual.mikrotik.com/docs/developer-guides/rest-api/) explains service and user
requirements; enabling the separate binary `api` service is not required for REST.

Create a dedicated user with `read`, `write`, `api` and `rest-api` policies.
The following RouterOS terminal example assumes the application connects from `192.168.50.20`.
Replace that address and the password before running it.
Restrict access to the web service with the router firewall:

```text
/user/group/add name=rdpr-api policy=read,write,api,rest-api
/user/add name=rdpr-api-user group=rdpr-api address=192.168.50.20/32 password="REPLACE_WITH_A_UNIQUE_PASSWORD"
/ip/service/set www disabled=no
```

In the UI/API RouterOS configuration, enter the router host without a URL scheme, the dedicated username/password,
and a managed list/table name such as `rdpr-networks`.
The updater manages the named firewall list, its `-strict` companion and the routing table with that name;
use names reserved for the application. The router must provide one active IPv4 default gateway for synchronization.
RouterOS synchronization currently supports IPv4 only (`type=4`).

### Run the container on RouterOS

Use the [RouterOS container guide](https://manual.mikrotik.com/docs/containers/) for the syntax supported by your
RouterOS version. Container mount and environment configuration can differ between releases.

1. Install the `container` package on a device matching the image's `amd64` or `arm64` platform.
1. Enable the container feature in device-mode and complete MikroTik's required confirmation procedure.
   A normal reboot does not substitute for confirmation; follow the CHR procedure when using a virtual router.
1. Create a veth interface with a reachable address and connect it to the intended bridge/network.
   Ensure the container can reach DNS/DoH, RIPEstat, list sources and the router's REST service.
1. Configure image storage and registry access, then use `gregorygost/gost-rdpr` with the chosen image tag.
1. Mount a persistent directory at `/app/db`, separate from the replaceable container root.
1. Set supported environment variables such as `ROOT_LOG_LEVEL` and `APP_LOG_LEVEL`, and start the container.

Use the container's IP address on port `80` for the UI and `/api/` access.
Port `4000` provides the direct API and Swagger UI.
Keep its network address consistent with the RouterOS API user's allowed source address.

#### RouterOS deployment example

Before adding the container, choose an unused IP address on an existing trusted bridge. Replace `bridge-lan`,
the address and gateway, and the `disk1` paths with values from your router. The mount maps the persistent
database directory to `/app/db`.

```text
/interface/veth/add name=veth-rdpr-example address=192.168.50.20/24 gateway=192.168.50.1
/interface/bridge/port/add bridge=bridge-lan interface=veth-rdpr-example
/container/mounts/add list=rdpr-example-db src=disk1/rdpr-example-db dst=/app/db
/container/envs/add list=rdpr-example-env key=ROOT_LOG_LEVEL value=info
```

If the router is configured to use a different registry, set the registry URL to Docker Hub.

```text
/container/config/set registry-url=https://registry-1.docker.io
```

```text
/container/add remote-image=gregorygost/gost-rdpr:dev interface=veth-rdpr-example envlist=rdpr-example-env \
  hostname=rdpr-example mountlists=rdpr-example-db root-dir=disk1/containers/rdpr-example \
  logging=yes comment="RDPR example" start-on-boot=yes name=rdpr-example
```

Check `/container/print` and wait for `status=stopped` after the image is downloaded and extracted. Then start it.

```text
/container/start rdpr-example
```

## Development

The backend requires Python **3.15 or later** and Poetry. Dependency constraints and resolved versions are in
[pyproject.toml](./pyproject.toml) and [poetry.lock](./poetry.lock). Install from the existing lockfile.

From the repository root in PowerShell, with Python 3.15 available as `python`:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
poetry install
.\.venv\Scripts\python.exe .\main.py
```

Local source execution starts the backend on port `4000`; the UI is maintained in its separate repository.
Startup creates/updates SQLite and starts background resources. Choose disposable database paths and safe settings
for development; do not point experiments at a production database or router.

### Checks

```powershell
.\.venv\Scripts\python.exe -m ruff check .
.\.venv\Scripts\python.exe -m ruff format --check .
.\.venv\Scripts\python.exe -m pyright --project pyproject.toml
.\.venv\Scripts\python.exe -m pytest -n 0 -m "not e2e_load"
.\.venv\Scripts\python.exe -m pytest -n 0 -m "not e2e_load" --cov `
  --cov-config=pyproject.toml --cov-report=term-missing --cov-report=html
```

Plain `pytest` selects unit tests by default. The commands above explicitly include integration and ordinary service
E2E tests. Load tests are separately selected with `-m e2e_load` and use disposable data and local protocol providers.
Coverage includes branches, has a configured threshold of 85%, and writes reports under `.pytest_cache/coverage/`.
Pyright checks the configured production paths; it does not type-check the test suite.

### Build a local image

The [Dockerfile](./Dockerfile) fetches and builds the UI, then packages it with the backend.
Build arguments include `UI_REPO_URL`, `UI_BRANCH`, `PYTHON_VERSION`, `NODE_VERSION`,
`PNPM_VERSION` and `POETRY_VERSION`.

```powershell
docker buildx build --platform linux/amd64 --load -t gost-rdpr:local .
```

Use `linux/arm64` when targeting that platform.
Run the result using the quick-start options with image `gost-rdpr:local`.

Codex contributors should start with [AGENTS.md](./AGENTS.md) and [CODEX_PROJECT.md](./CODEX_PROJECT.md).

## License and author

The project is distributed under [GPL v3](./LICENSE), without warranty. External dependencies retain their own licenses.

GregoryGost - <https://gregory-gost.ru>
