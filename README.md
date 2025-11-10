# GOST RDPR (Resolve Domains Per Record)

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

## Application URLs

- `/docs` Swagger/OpenAPI docs
- `/docs/openapi.json` Swagger/OpenAPI json file for export->import to external OpenApi viewer
- `/metrics` - Prometheus metrics

## Environment variables

Available environment variables

| ENV PARAMETER | Type | Default value | Description |
|---------------|------|---------------|-------------|
| `ROOT_PATH`   | str  | `normpath(getcwd())` | Path to the application root folder |
| `ROOT_LOG_LEVEL` | str | `error` | Root level logging |
| `APP_TITLE` | str | `GOST-RDPR (Resolve Domains Per Records)` | Application name |
| `APP_SUMMARY` | str | `A utility for working with Mikrotik RouterOS and BGP protocol for announcing IP addresses` | Description title |
| `APP_DESCRIPTION` | str | `The utility provides parsing of domain names into IP addresses, processing of domain lists and their subsequent parsing, processing of individual IP addresses and summarized IP groups. Updates firewall address list and routing table` | Detailed description of the application |
| `APP_DEBUG` | str | `False` | FastAPI application debug level |
| `APP_VERSION` | str | `2.0.0` | Application version |
| `APP_HOST`    | str  | `0.0.0.0`   | Listen on IP addr. `0.0.0.0` - Listen on all IP addresses |
| `APP_PORT` | int | `4000` | Listen on TCP/IP specific port |
| `APP_LOG_LEVEL` | str | `error` | Application level logging |
| `QUEUE_MAX_SIZE` | int | `1000` | Maximum size of each individual queue |
| `QUEUE_GET_TIMEOUT` | float | `0.1` | Maximum waiting time for a queue entry. 0.1s = 100ms |
| `QUEUE_SLEEP_TIMEOUT` | float | `0.01` | The maximum wait time while the queue is empty. At the same time, the infinite loop should allow the scheduler to integrate other tasks into the overall flow. 0.01s = 10ms |
| `DB_LOG_LEVEL` | str | `error` | SQLAlchemy level logging |
| `DB_TIMEOUT` | float | `30.0` | Maximum time to wait for a database to be freed |
| `DB_BASE_DIR` | str | `db` | A separate folder containing the database. It is also later mounted in a container for downloading to a local PC |
| `DB_FILE_NAME` | str | `rdpr-db.sqlite` | Database file name |
| `DB_TABLE_PREFIX` | str | `rdpr_` | Prefix for database table names |
| `DB_SAVE_BATCH_SIZE` | int | `1000` | The maximum number of all insert, update, and delete events in the database queue. This means we write a maximum of 1000 events to the file at a time (which can be very frequent). But you should also look at the timeout parameter |
| `DB_SAVE_BATCH_TIMEOUT` | float | `0.5` | If we haven't accumulated a batch of the size limited by the parameter "parameter1" within the interval specified here, then we do what's already in the current batch |
| `ATTEMPTS_LIMIT` | int | `5` | How many times a file must be checked with a negative result before it (and all its child entities) are deleted from the database |
| `REQ_CONNECTION_RETRIES` | int | `3` | Requests will be retried the given number of times in case an `httpx.ConnectError` or an `httpx.ConnectTimeout` occurs, allowing smoother operation under flaky networks |
| `REQ_TIMEOUT_DEFAULT` | float | `20.0` | General timeout for connections parameters `connect`, `read`, `write` or `pool` |
| `REQ_TIMEOUT_CONNECT` | float | `20.0` | Individual timeout for `connect` |
| `REQ_TIMEOUT_READ` | float | `30.0` | Individual timeout for `read` |
| `REQ_MAX_CONNECTIONS` | int | `5` | The maximum number of allowable connections. `None` for no limits |
| `REQ_MAX_KEEPALIVE_CONNECTIONS` | int | `30` | Number of allowable keep-alive connections. `None` to always allow |
| `REQ_SSL_VERIFY` | bool | `True` | When making a request over HTTPS, HTTPX needs to verify the identity of the requested host. To do this, it uses a bundle of SSL certificates (a.k.a. CA bundle) delivered by a trusted certificate authority (CA). You can disable SSL verification completely and allow insecure requests |
| `DOMAINS_FILTERED_MIN_LEN` | int | `3` | The minimum domain length required to save it to the database. This is necessary to filter out empty domains that, for some reason, are generated in MikroTik scripts |
| `DOMAINS_UPDATE_INTERVAL` | int | `172800` | Domain selection period. This means that if a domain has been processed, it will not be processed again until this period has passed. Specified in seconds. 172800s = 2days |
| `DOMAINS_RESOLVE_SEMAPHORE_LIMIT` | int | `60` | Limit of concurrent domain resolving tasks |
| `DOMAINS_BLACK_LIST` | str | `None` | Domains that should not be included in the database. Comma-separated list |
| `LISTS_UPDATE_INTERVAL_SEC` | int | `604800` | The period after which the file must be uploaded and verified again. Specified in seconds. 604800s = 7days |
| `IP_NOT_ALLOWED` | str | `127.0.0.1, 0.0.0.0, 0.0.0.0/0, ::, ::/0` | A list of IP addresses that should not be included in the database. Comma-separated list. |
| `ROS_REST_API_READ_TIMEOUT`| float | `59.0` | ROS REST API server timeout = 60s |

Special environment variable

- `ROOT_PASS` - Password for SSH in docker container. Default: autogenerated(see in log output)

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

Python version >= `3.14`

Create virtual env

```shell
python -m venv .venv
python3.14 -m venv .venv
```

Or special python version on Win

```powershell
& 'C:\Program Files\Python\Python3.14\python.exe' -m venv .venv
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

Install libs from requirements.txt

```shell
pip install -r requirements.txt
```

or manual install libs

```shell
pip install fastapi
pip install SQLAlchemy
pip install aiosqlite
pip install dnspython
pip install uvicorn
pip install httpx
pip install pydantic-settings
pip install opentelemetry-exporter-prometheus
pip install cashews
```

or upgrade libs (not recomend)

```shell
pip list -o
pip install [package_name] --upgrade
```

Freeze requirements

```shell
pip freeze > requirements.txt
```

### TODO

- ADD NEW JOB - check if IP addresses are included in a wider mask (summarization)
- WEB UI (extended project/docker - Vue.js 3) - GOST-RDPR-UI

### Build docker images

Build docker image for RouterOS CHR `x86_64` and `ARM64` device

```shell
# first run
docker buildx create --driver=docker-container --name build-container

# all after first run
docker buildx use build-container

# Build for amd64(x86_64) and arm64 without arguments
# PROD
docker buildx build --no-cache --platform linux/amd64,linux/arm64 --push -t gregorygost/gost-rdpr .
# Spec PROD version
docker buildx build --no-cache --platform linux/amd64,linux/arm64 --push -t gregorygost/gost-rdpr:latest -t gregorygost/gost-rdpr:2.0.1 .
# DEV
docker buildx build --no-cache --platform linux/amd64,linux/arm64 --push -t gregorygost/gost-rdpr:dev .
```

```shell
# run docker after build
docker run -d -p 8080:4000 -e LOG_LEVEL='debug' --memory=1024m --cpus="1" --restart unless-stopped gregorygost/gost-rdpr
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
`requirements.txt`.

## About

GregoryGost - <https://gregory-gost.ru>
