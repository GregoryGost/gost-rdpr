# GOST RDPR (Resolve Domain Per Record)

Docker HUB - <https://hub.docker.com/r/gregorygost/gost-rdpr>

A utility for working with Mikrotik RouterOS and BGP protocol for announcing IP addresses.

The utility provides parsing of domain names into IP addresses, processing of domain lists and their subsequent parsing,
processing of individual IP addresses and summarized IP groups. Updates firewall address list and routing table.

Docker support OS/ARCH:

- linux/amd64
- linux/arm64

## URLS

- `/docs` Swagger/OpenAPI docs
- `/docs/openapi.json` Swagger/OpenAPI json file for export->import to external OpenApi viewer
- `/monitoring` - Prometheus FastAPI metrics

## Environments

Arguments / Environments

- `ROOT_PASS` - Password for SSH. Default: autogenerated(see in log output)
- `IS_PRODUCTION` - Default: `True`
- `HOST` - Listen on IP addr. Default: `0.0.0.0`
- `PORT` - Listen TCP port. Default: `4000`
- `LOG_LEVEL` - Logging level for app (not requests ib). Default: `error`
- `DOMAINS_UPDATE_INTERVAL` - The interval since the date the domains was last processed. Do not take recently processed
  ones. Default: `172800` - 2 days
- `DB_FLUSH_BATCH_SIZE` - Maximum size of the number of processed IP addresses that will be written to the database at
  one time. It is more efficient to write in batches. Default: `1000`
- `THREADS_COUNT` - Maximum number of threads. Only slicing is used to process bundles creates threads greater than the
  set limit. Default: `1` OR `cpus > 3 cpu=(cpus - 1)`
- `QUEUE_SIZE` - Domains queue and DB queue size. Default: `100`
- `RESOLVE_DOMAINS_BATCH_SIZE` - Bundle size for one-time processing of domains. Generates a threadsPool with requests
  for domain resolving. Default: `50`
- `RESOLVE_EMPTY_ITER` - How many iterations to wait before finally dropping the batch into the queue. Default: `100`
- `DB_EMPTY_ITER` - How many iterations to wait before the final dropping of the batch into the database. Default:
  `RESOLVE_EMPTY_ITER + 50`

## RouterOS

RouterOS v7 only

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
add key=THREADS_COUNT name=rdpr-envs value=2
# setup mounts
/container/mounts/add dst=/app/db name=rdpr-db src=/container/gost-rdpr-db
# setup container
/container
add remote-image=gregorygost/gost-rdpr:latest interface=LAN-VEth1 envlist=rdpr-envs hostname=gost-rdpr mounts=rdpr-db \
root-dir=container/gost-rdpr logging=yes comment=GOST-RDPR start-on-boot=yes
```

## Contrib

Python version >= `3.13.0`

Create virtual env

```shell
python -m venv .venv
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
pip install librouteros
pip install prometheus-fastapi-instrumentator
```

or upgrade libs

```shell
pip list -o
pip install [package_name] --upgrade
```

Freeze requirements

```shell
pip freeze > requirements.txt
```

### TODO

- JOB - check if IP addresses are included in a wider mask (summarization)
- Refactor to OOP Class implement and application arch
- Distributed storage of route files FastAPI
- WEB UI (extended project/docker - VueJS-3)

### Build docker images

Build docker image for RouterOS CHR x86_64 and ARM64 device

```shell
docker buildx create --driver=docker-container --name build-container
docker buildx use build-container
# Build for amd64(x86_64) and arm64 without arguments
docker buildx build --no-cache --platform linux/amd64,linux/arm64 --push -t gregorygost/gost-rdpr .
# Build for amd64(x86_64) and arm64 with arguments
docker buildx build --no-cache --platform linux/amd64,linux/arm64 --build-arg IS_PRODUCTION='False' \
--build-arg HOST='0.0.0.0' --build-arg LOG_LEVEL='info' --push -t gregorygost/gost-rdpr .
```

```shell
# run docker after build
docker run -d -p 8080:4000 -e LOG_LEVEL='debug' --memory=1024m --cpus="1" --restart unless-stopped gregorygost/gost-rdpr
```

## Licensing

All source materials for the project are distributed under the [GPL v3](./LICENSE "License Description") license. You
can use the project in any form, including for commercial activities, but it is worth remembering that the author of the
project does not provide any guarantees for the performance of the executable files, and also does not bear any
responsibility for claims or damage caused.

This application uses external modules. The authors of these modules are (or are not) responsible for the quality and
stability of their work. See the licenses of these modules. External modules are listed in the dependencies file of the
package.json.

## About

GregoryGost - <https://gregory-gost.ru>
