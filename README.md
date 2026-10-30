# GOST RDPR (Resolve Domains Per Record)

REPO - <https://github.com/GregoryGost/gost-rdpr>
Docker HUB - <https://hub.docker.com/r/gregorygost/gost-rdpr>

- `latest` tag
- `dev` tag
- `x.x.x` version tag

A utility for working with Mikrotik RouterOS and BGP protocol for announcing IP addresses.

The utility provides parsing of domain names into IP addresses, processing of domain lists and their subsequent parsing,
processing of individual IP addresses and summarized IP groups. Updates firewall address list and routing table.

Docker support OS/ARCH:

- linux/amd64
- linux/arm64

## UI Dashboard

An interface has been developed for the program. Its source code is located in a separate repository.
It can be embedded in a Docker container and is accessible along with the API methods and OpenAPI documentation.

UI REPO - <https://github.com/GregoryGost/gost-rdpr-ui>

<table>
  <tr>
    <td width="50%">
      <img src="docs/screenshots/dashboard-dark.png" alt="Dashboard Home page example" />
      <p align="center"><i>Home page example</i></p>
    </td>
    <td width="50%">
      <img src="docs/screenshots/domains-page-dark.png" alt="Dashboard Domains Page example" />
      <p align="center"><i>Domains Page example</i></p>
    </td>
  </tr>
</table>

## Application URLs

- `/docs` Swagger/OpenAPI docs
- `/docs/openapi.json` Swagger/OpenAPI json file for export->import to external OpenApi viewer
- `/metrics` - Prometheus metrics

## Environment variables

Available environment variables

| ENV PARAMETER | Type | Default value | Description |
| --------------- | ------ | --------------- | ------------- |
| `ROOT_PATH` | str | `normpath(getcwd())` | Path to the application root folder |
| `ROOT_LOG_LEVEL` | str | `error` | Root level logging |
| `APP_TITLE` | str | `GOST-RDPR (Resolve Domains Per Records)` | Application name |
| `APP_SUMMARY` | str | `A utility for working with Mikrotik RouterOS and BGP protocol for announcing IP addresses` | Description title |
| `APP_DESCRIPTION` | str | `The utility provides parsing of domain names into IP addresses, processing of domain lists and their subsequent parsing, processing of individual IP addresses and summarized IP groups. Updates firewall address list and routing table` | Detailed description of the application |
| `APP_DEBUG` | str | `False` | FastAPI application debug level |
| `APP_VERSION` | str | `2.0.0` | Application version. Get in config from `pyproject.toml` file |
| `APP_HOST` | str | `0.0.0.0` | Listen on IP addr. `0.0.0.0` - Listen on all IP addresses |
| `APP_PORT` | int | `4000` | Listen on TCP/IP specific port |
| `APP_LOG_LEVEL` | str | `error` | Application level logging |
| `QUEUE_MAX_SIZE` | int | `1000` | Maximum size of each individual queue |
| `QUEUE_GET_TIMEOUT` | float | `0.1` | Maximum waiting time for a queue entry. 0.1s = 100ms |
| `QUEUE_SLEEP_TIMEOUT` | float | `0.01` | The maximum wait time while the queue is empty. At the same time, the infinite loop should allow the scheduler to integrate other tasks into the overall flow. 0.01s = 10ms |
| `RESOLVE_DOMAINS_LOG_EVERY` | int | `10` | Specifies the number of messages that will be logged during domain resolution. Distributes the total volume of domains to resolve among this number |
| `DB_LOG_LEVEL` | str | `error` | SQLAlchemy level logging |
| `DB_TIMEOUT` | float | `30.0` | Maximum time to wait for a database to be freed |
| `DB_BASE_DIR` | str | `db` | A separate folder containing the database. It is also later mounted in a container for downloading to a local PC |
| `DB_FILE_NAME` | str | `rdpr-db.sqlite` | Database file name |
| `DB_TABLE_PREFIX` | str | `rdpr_` | Prefix for database table names |
| `DB_SAVE_BATCH_SIZE` | int | `1000` | The maximum number of all insert, update, and delete events in the database queue. This means we write a maximum of 1000 events to the file at a time (which can be very frequent). But you should also look at the timeout parameter |
| `DB_SAVE_BATCH_TIMEOUT` | float | `5.0` | Maximum time in seconds from the first event in a pending batch until that partial batch is flushed |
| `DB_SHUTDOWN_TIMEOUT` | float | `20.0` | Time in seconds to wait for the database writer during shutdown. Expiry reports unresolved writes; it does not imply a successful drain |
| `DB_TUNE_JOURNAL_MODE` | str | `WAL` | Write-Ahead Logging - better concurrent access |
| `DB_TUNE_WAL_AUTOCHECKPOINT` | int | `1000` | Initiate a checkpoint approximately every 1000 WAL pages (choose experimentally: if WAL grows too quickly, decrease it; if checkpoints interfere, increase it) |
| `DB_TUNE_SYNCHRONOUS` | str | `NORMAL` | NORMAL - A good balance of performance and reliability for most VDS applications. `FULL`` provides maximum reliability, but is more expensive in terms of I/O. |
| `DB_TUNE_TEMP_STORE` | str | `FILE` | Defines where SQLite stores temporary tables and indexes. `MEMORY` can improve performance but increases memory consumption |
| `DB_TUNE_MMAP_SIZE` | int | `0` | Defines the maximum amount of database file memory mapping. `0` disables memory-mapped I/O. Higher values may improve read performance but increase container memory usage |
| `DB_TUNE_CACHE_SIZE` | int | `-2048` | If the value is negative, SQLite treats it as kibibytes; `-2048` means about 2 MiB cache. Positive values are interpreted as number of database pages. Lower values reduce RAM usage; higher values may improve performance at the cost of memory |
| `DB_TUNE_BUSY_TIMEOUT` | int | `2000` | This is the timeout (in milliseconds) during which SQLite will retry acquiring a lock instead of immediately failing with a "database is locked" error. Defaults in SQLite to 0 (no wait). |
| `DB_POOL_SIZE` | int | `10` | The number of connections to keep open inside the connection pool |
| `DB_POOL_RECYCLE` | int | `1500` | This setting causes the pool to recycle connections after the given number of seconds has passed |
| `DB_POOL_TIMEOUT` | int | `30` | Number of seconds to wait before giving up on getting a connection from the pool |
| `DB_POOL_SIZE_OVERFLOW` | int | `2` | The number of connections to allow in connection pool `overflow`, that is connections that can be opened above and beyond the `db_pool_size` setting, which defaults to five |
| `ATTEMPTS_LIMIT` | int | `5` | How many times a file must be checked with a negative result before it (and all its child entities) are deleted from the database |
| `HTTPX_LOG_LEVEL` | str | `error` | HTTPX logging level |
| `REQ_CONNECTION_RETRIES` | int | `3` | Requests will be retried the given number of times in case an `httpx.ConnectError` or an `httpx.ConnectTimeout` occurs, allowing smoother operation under flaky networks |
| `REQ_TIMEOUT_DEFAULT` | float | `20.0` | General timeout for connections parameters `connect`, `read`, `write` or `pool` |
| `REQ_TIMEOUT_CONNECT` | float | `20.0` | Individual timeout for `connect` |
| `REQ_TIMEOUT_READ` | float | `30.0` | Individual timeout for `read` |
| `REQ_MAX_CONNECTIONS` | int | `5` | The maximum number of allowable connections. `None` for no limits |
| `REQ_MAX_KEEPALIVE_CONNECTIONS` | int | `30` | Number of allowable keep-alive connections. `None` to always allow |
| `REQ_SSL_VERIFY` | bool | `True` | When making a request over HTTPS, HTTPX needs to verify the identity of the requested host. To do this, it uses a bundle of SSL certificates (a.k.a. CA bundle) delivered by a trusted certificate authority (CA). You can disable SSL verification completely and allow insecure requests |
| `REQ_DEFAULT_LIMIT` | int | `100` | Maximum number of records returned by a paginated API request |
| `DOMAINS_FILTERED_MIN_LEN` | int | `3` | The minimum domain length required to save it to the database. This is necessary to filter out empty domains that, for some reason, are generated in MikroTik scripts |
| `DOMAINS_UPDATE_INTERVAL` | int | `172800` | Domain selection period. This means that if a domain has been processed, it will not be processed again until this period has passed. Specified in seconds. 172800s = 2days |
| `DOMAINS_RESOLVE_SEMAPHORE_LIMIT` | int | `60` | Limit of concurrent domain resolving tasks |
| `DOMAINS_RESOLVE_NEW_BATCH_SIZE` | int | `500` | Limit for sampling the number of domains that have never been processed |
| `DOMAINS_RESOLVE_STALE_BATCH_SIZE` | int | `2000` | Limit for sampling the number of previously processed domains |
| `DOMAINS_BLACK_LIST` | str | `None` | Domains that should not be included in the database. Comma-separated list |
| `LISTS_UPDATE_INTERVAL_SEC` | int | `604800` | The period after which the file must be uploaded and verified again. Specified in seconds. 604800s = 7days |
| `IP_NOT_ALLOWED` | str | `0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.0.2.0/24, 192.88.99.0/24, 192.168.0.0/16, 198.18.0.0/15, 198.51.100.0/24, 203.0.113.0/24, 224.0.0.0/4, 240.0.0.0/4, ::/128, ::1/128, fc00::/7, fe80::/10, ff00::/8, 2001:db8::/32` | Comma-separated CIDR networks that must not be saved in the database. |
| `ROS_REST_API_READ_TIMEOUT` | float | `59.0` | ROS REST API server timeout = 60s |
| `ROS_REST_API_DEFAULT_TIMEOUT` | float | `59.0` | Default timeout for RouterOS REST API requests |
| `RIPE_STAT_BASE_URL` | str | `https://stat.ripe.net` | RIPEstat API base URL for IPv4 prefix lookups |
| `RIPE_STAT_REQUESTS_SEMAPHORE_LIMIT` | int | `5` | Maximum number of concurrent RIPEstat prefix lookups during domain resolving |
| `RIPE_STAT_CACHE_SIZE` | int | `10000` | Maximum number of RIPEstat prefix records in the in-memory cache |
| `RIPE_STAT_PREFIX_CACHE_TTL_SEC` | int | `28800` | TTL in seconds for a RIPEstat result with a prefix |
| `RIPE_STAT_EMPTY_PREFIX_CACHE_TTL_SEC` | int | `3600` | TTL in seconds for a RIPEstat result without a prefix |
| `RIPE_STAT_CACHE_LOCK_TTL_SEC` | int | `120` | Maximum lifetime in seconds of a per-IP RIPEstat cache lock |

## Database writes and shutdown

Runtime database changes pass through one bounded in-memory writer queue. Enqueue success means that a command was
accepted into memory; it does not confirm commit or immediate visibility to reads. A full batch is flushed immediately,
and a partial batch is flushed at its deadline or during graceful shutdown.

Only SQLite busy/locked failures before commit are retried, after the failed transaction has been rolled back and
released. The same batch stays ahead of later commands, with at most three attempts and delays of 0.1 and 0.2 seconds.
Commit errors and cancellation are not automatically replayed because their persistence outcome can be unknown.
On a permanent failure, the writer rejects further commands and reports pending or unknown outcomes instead of
discarding the failed batch. The nonblocking IP-record deletion API retains its boolean rejection result.

The writer applies the configured SQLite settings to its active session, including foreign-key constraints and
deletion cascades. A resolution command referencing a domain that has already been deleted fails its batch rather
than creating orphan IP records; the normal terminal-failure policy then applies.

Graceful shutdown closes queue admission, finishes accepted commands and the final partial batch, then releases the
database engines. A deadline or forced cancellation reports unresolved work and retains ownership of any ongoing
cleanup. `DB_SHUTDOWN_TIMEOUT` covers the database wait, not the total application or container shutdown time.
The queue is process-local and does not recover pending commands after a crash or forced process termination.

## Resolution measurements

`/metrics` exposes separate measurements for processing, queue admission and confirmed database commands.
All durations use monotonic clocks and seconds. Nested phase durations overlap and must not be added as wall time.

| Metric family | Meaning |
| ------------- | ------- |
| `httpx_requests_total` | Started transport exchanges, including failures without a response |
| `httpx_responses_total` | Exchanges that received response headers, grouped by HTTP status |
| `httpx_requests_duration_seconds` | Transport entry to the first stream terminal; includes consumer pauses |
| `httpx_request_headers_duration_seconds` | Transport entry to response headers or a transport error |
| `httpx_exchanges_started_total`, `httpx_exchanges_terminal_total`, `httpx_exchanges_in_flight` | Exchange lifecycle conservation by integration |
| `httpx_exchange_duration_seconds` | Full exchange lifecycle by integration, terminal phase and outcome |
| `httpx_stream_cleanup_errors_total` | Cleanup failures after an already observed stream terminal |
| `resolution_dns_duration_seconds`, `resolution_dns_semaphore_wait_seconds` | DNS query/validation and semaphore wait by server ID, transport, record type and outcome |
| `resolution_ripe_duration_seconds` | RIPEstat cache, lock, network and logical lookup phases |
| `resolution_queue_duration_seconds` | Queue admission, residence and pending-batch waits |
| `resolution_writer_duration_seconds` | Write attempts, transactions, commit and cleanup phases |
| `resolution_run_events_total`, `resolution_run_elapsed_seconds` | Cumulative run events and processing duration |
| `resolution_run_snapshot` | Fields of the latest started run for each `new`, `stale` or `stored` mode |

HTTP measurements observe each transport exchange separately; redirects and authentication exchanges can create
several exchanges for one logical request. Existing connection retries remain inside an exchange. A completed stream
does not imply a successful HTTP status, DNS result or JSON payload. Unconsumed, unclosed streams remain in flight.
Metrics never consume response bodies. Legacy HTTP exception labels retain their names, with `host` and `path`
set to `redacted` and errors mapped to fixed categories.

DNS `server_id` is the existing configuration row ID, including the fallback row `0`; use the DNS API to identify it.
It is not an immutable endpoint identity. Historical ID series last for the process lifetime, and reused SQLite IDs
aggregate under that key. Configuration churn can increase historical series. Queried domains, addresses, URLs,
credentials and run IDs are not metric labels. CNAME `no_alias` does not prove absence of IPv4 addresses.

Run processing outcomes are `success`, `partial`, `failure` and actual processing cancellation. Confirmed absence
of addresses is successful evidence. Partial evidence remains partial even when no new addresses require a write.
Admission failure is separate from an already established processing result. Best-effort CNAME discovery and RIPEstat
fallback have their own observations.

Persistence fields distinguish `admitted`, `pending`, `confirmed`, `known_not_committed` and `unknown`, plus rejected
admission and results needing no write. `confirmed` means a source-domain result command had a known commit, including
partial results; it does not count inserted IP rows, CNAME commands or records surviving a later deletion. Retry
attempts do not increase confirmed counts. A known commit remains confirmed after cleanup failure. An ambiguous
commit remains unknown; an interrupted in-flight operation can acquire a known outcome later.

The processing summary uses the existing job completion boundary and does not wait for the database writer.
Later receipts update persistence statistics. `processing_rate` counts attempted domains per processing second;
compare success/partial/failure counts alongside that rate. `saved_rate` counts confirmed result commands per second
through processing and known persistence completion. Final rates have explicit `*_rate_valid` fields; unknown,
interrupted or zero-duration measurements are invalid and use `NaN`, rather than a fabricated zero. A completed run
with no required writes can have a valid saved rate of zero. Late receipts from an older run cannot replace a newer
run's snapshot for the same mode. All observations are process-local and do not provide crash durability.

### Repeatable local baseline

The explicitly selected `e2e_load` scenarios use the real application entrypoint and lifespan, disposable SQLite,
and local DNS, DoH and RIPEstat protocol providers. They record fixed workloads and safe settings, cold/warm cache
conditions, fast/slow/unavailable providers, processing and persistence measurements, actual database effects and
application-process resources. These results describe the local test environment, not production provider latency.

On Windows, select a fresh temporary directory so the run owns all generated files:

```powershell
$measurementTemp = Join-Path ([System.IO.Path]::GetTempPath()) ('rdpr-measurements-' + [guid]::NewGuid().ToString('N'))
.\.venv\Scripts\python.exe -B -m pytest -n 0 -m e2e_load -p no:cacheprovider --basetemp $measurementTemp
```

Keep the exact source snapshot, dependency versions, workload, provider schedule, settings and generated results
when comparing later changes. Resource measurements must use the actual application PID; a virtual-environment
launcher PID and unavailable process metrics must not be substituted for application CPU or resident memory.

The initial local baseline was recorded on 2026-10-31, Windows AMD64, Python 3.15.2, HTTPX 0.28.1,
SQLAlchemy 2.1.6, aiosqlite 0.22.1, dnspython 2.9.1, cashews 7.6.0 and prometheus-client 0.26.0.
It used four fixed domains, two local DNS transports and sixteen A/CNAME queries per run. Relevant explicit settings
were `DB_SAVE_BATCH_SIZE=1000`, `DB_SAVE_BATCH_TIMEOUT=0.05`, `QUEUE_MAX_SIZE=1000`,
`DOMAINS_RESOLVE_SEMAPHORE_LIMIT=20`, `RIPE_STAT_REQUESTS_SEMAPHORE_LIMIT=5`,
`REQ_CONNECTION_RETRIES=0` and two-second HTTP timeouts. These are controlled test settings.

| Provider / cache | Attempts per second | Confirmed commands per second | DNS p95 estimate, ms |
| ---------------- | -------------------: | ----------------------------: | -------------------: |
| Fast / cold | 19.152 | 18.056 | 43.3 |
| Fast / warm | 21.308 | 19.869 | 40.0 |
| Slow, 20 ms / cold | 9.152 | 8.005 | 55.0 |
| Slow, 20 ms / warm | 8.624 | 7.602 | 71.7 |
| Disconnected DoH and DNS SERVFAIL / cold | 36.093 | 0.000 | 22.6 |
| Disconnected DoH and DNS SERVFAIL / warm | 39.639 | 0.000 | 22.6 |

Each unavailable run had four failed attempts and zero confirmed commands. RIPEstat made two network lookups with
a cold cache and none with a warm cache; unavailable runs needed no RIPEstat lookup. The measured application CPU
deltas were 0.078125–0.296875 seconds; process-lifetime peak resident memory was 119,140,352–120,176,640 bytes.
Histogram quantiles are interpolated bucket estimates. The workload is a small reproducibility baseline with
metrics polling, and the numbers include its observation overhead. Repeat runs under comparable host load before
attributing a difference to application code.

The tested source/configuration snapshot identity is
`2237ef45537716d78b14507e3080baaf92d860a8dcb00922b83fbaa2c6d8b609`, based on commit `1a96db7` plus the
measurement changes. Each rerun writes `measurement-baseline.json` under its pytest temporary directory with the
exact invocation, input hashes, versions, settings, provider schedule, outcomes, database effects and resource samples.

## MikroTik RouterOS

RouterOS v7 only !!! RouterOS v6 NOT supported !!!

- bridge interface has already been created earlier

You need to activate the container functionality through the device-mod. On different virtual servers, reboot may work
as a simple reboot command rather than a hard power-down (which is required to enable the functionality correctly). In
this case, you need to apply the snapshot technique. You need to capture the snapshot and deploy it immediately after
the command is issued and do not exit the RouterOS terminal while doing so.

```shell
# enable container device-mode
/system/device-mode/update container=yes
```

```shell
# setup network interface
/interface/veth/add address=192.168.50.20/24 comment="Container LAN" gateway=192.168.50.1 gateway6="" name=LAN-VEth1
/interface/bridge/port/add bridge=LAN-Bridge interface=LAN-VEth1
# setup containers config
/container/config/set ram-high=256M registry-url=https://registry-1.docker.io tmpdir=container/tmp
# setup environments
/container/envs/
add key=LOG_LEVEL name=rdpr-envs value=info
add key=ROOT_PASS name=rdpr-envs value=123456789
# setup mounts
/container/mounts/add dst=/app/db name=rdpr-db src=/container/gost-rdpr-db
# setup container
/container
add remote-image=gregorygost/gost-rdpr:latest interface=LAN-VEth1 envlist=rdpr-envs hostname=gost-rdpr mounts=rdpr-db \
root-dir=container/gost-rdpr logging=yes comment=GOST-RDPR start-on-boot=yes
```

You need to create a separate group and user for it

```shell
# add API group
/user/group/add name=api policy=read,write,api,rest-api,!local,!telnet,!ssh,!ftp,!reboot,!policy,!test,!winbox,!password,!web,!sniff,!sensitive,!romon
# enable www and api services
/ip/service/
set www address=192.168.50.20/24
set api address=192.168.50.20/24
# create user
/user/add group=api name=rdpr-api-user
```

## Patch notes / Changelog

[CHANGELOG.md](./CHANGELOG.md "Changelog / Patch notes")

## For contrib

Codex contributors: start with [AGENTS.md](./AGENTS.md) and the project profile in
[CODEX_PROJECT.md](./CODEX_PROJECT.md).

Python version >= `3.15`

How to alt install python 3.15 in WSL Debian

```sh
sudo apt update
sudo apt install pkg-config build-essential zlib1g-dev libncurses5-dev libgdbm-dev \
  libnss3-dev libssl-dev libreadline-dev libffi-dev libsqlite3-dev -y
wget https://www.python.org/ftp/python/3.15.2/Python-3.15.2.tgz
tar -xzvf Python-3.15.2.tgz
cd Python-3.15.2
dpkg-architecture --query DEB_BUILD_GNU_TYPE # use in --build next ./configure
./configure --build="x86_64-linux-gnu" --prefix=/usr/local --enable-optimizations \
  --enable-loadable-sqlite-extensions --enable-option-checking=fatal --enable-shared \
  LDFLAGS="-Wl,-rpath /usr/local/lib" --with-ensurepip
nproc # if output 20 CPUS use 18
sudo make -j 18
sudo make altinstall
python3.15 -VV
```

example output

```sh
Python 3.15.2 (tags/v3.15.2:5e58eaa, Oct 25 2026, 17:27:03) [MSC v.1951 64 bit (AMD64)]
```

Create virtual env

```sh
python3.15 -m venv .venv
```

Or Windows

```powershell
& 'C:\Program Files\Python315\python.exe' -m venv .venv
```

Activate venv

```powershell
.\.venv\Scripts\activate
```

```shell
source .venv/bin/activate
```

Upgrade pip

```shell
python -m pip install --upgrade pip
```

Install libs from lock poetry file

```shell
poetry install
```

or manual install libs

```sh
pip install --upgrade poetry
pip install poetry
poetry init
```

```shell
poetry add fastapi
poetry add SQLAlchemy
poetry add aiosqlite
poetry add aiosqlitepool
poetry add dnspython
poetry add uvicorn
poetry add httpx
poetry add pydantic-settings
poetry add opentelemetry-exporter-prometheus
poetry add cashews
```

or upgrade libs (not recomend)

```sh
poetry add "fastapi^0.139.2"
```

Get tree all modules

```sh
poetry show --tree
poetry show --outdated
```

### TODO

- ADD NEW JOB - check if IP addresses are included in a wider mask (summarization)

### Build docker images

Build docker image for RouterOS CHR `AMD64(x86_64)` and `ARM64` device

```shell
# first run
docker buildx create --driver=docker-container --name build-container

# all after first run
docker buildx use build-container

# Build for amd64(x86_64) and arm64 without arguments
# PROD
docker buildx build --no-cache --platform linux/amd64,linux/arm64 --push -t gregorygost/gost-rdpr .
# Spec PROD version
docker buildx build --no-cache --platform linux/amd64,linux/arm64 --push \
  -t gregorygost/gost-rdpr:latest -t gregorygost/gost-rdpr:2.0.1 .
# DEV
docker buildx build --no-cache --platform linux/amd64,linux/arm64 --push -t gregorygost/gost-rdpr:dev .
# TEST in builder
docker buildx build --no-cache --progress=plain --platform linux/amd64 --load \
  -t gregorygost/gost-rdpr:dev --builder=build-container .

# Local build (only one platform amd64 or arm64 ... etc.)
docker buildx build --no-cache --platform linux/amd64 --output=type=docker -t gregorygost/gost-rdpr:dev .
docker save gregorygost/gost-rdpr:dev > gost-rdpr_amd64_2.0.9-dev.tar
```

```shell
# run docker after build
docker run --name gost-rdpr -p 8080:80 -p 5000:4000 -e LOG_LEVEL='debug' \
  --memory=1024m --cpus="1" --restart unless-stopped -d gregorygost/gost-rdpr
# simple
docker run --name gost-rdpr-dev -p 8080:80 -p 5000:4000 -d gregorygost/gost-rdpr:dev
# enter in docker shell
docker exec -it gost-rdpr-dev bash
```

```shell
docker buildx prune
docker image prune -a
```

## Docs

- [Asyncio FIFO Queue in Python](https://habr.com/ru/articles/764932/)

## Licensing

All source materials for the project are distributed under the [GPL v3](./LICENSE "License Description") license. You
can use the project in any form, including for commercial activities, but it is worth remembering that the author of the
project does not provide any guarantees for the performance of the executable files, and also does not bear any
responsibility for claims or damage caused.

This application uses external modules. The authors of these modules are (or are not) responsible for the quality and
stability of their work. See the licenses of these modules. External modules are listed in the dependencies file of the
`pyproject.toml`.

## About

GregoryGost - <https://gregory-gost.ru>
