# Changelog / Patch notes

## `04.11.2025` - version **2.0.0**

- OOP arch implement
- SQLAlchemy async ORM for SQLite DB. Insertion, updating, and deletion are now performed in a single queue, since the database is a single file and locks must be avoided
- Change ros_configs field `pass` to `passwd`
- Change POST answer always `OK` (reason: background task insert to database)
- Add `search` methods for all sections [GET] all
- Change format POST add ip addresses
- The list loading process has been redesigned; non-existent domains/ips are now removing
- Change Environments variables (see README.md)
- All thread pools have been removed, and a complete transition to asynchronous functions via asyncio has been implemented
- Prometheus metrics have been added. They are available at `/metrics`
- Upgrade to the new stable version of Python `3.14`
- Domain length validation has been removed. Instead, shorter domains are now rejected before being saved to the database to avoid acceptance errors
- Domains black list
- Support migrations scripts for Database. There is no need to touch the old database the migration will happen automatically.
- Change ips lists load commands. Now this is a single command for loading all lists, both domains and IP addresses. New `/commands/lists/load`. Old `/commands/domains/lists/load` and `/commands/ips/lists/load`
- Change path RoS configs. New `/ros`. Old `/ros/config`
- Jobs methods removed. Jobs table removed from Database. Jobs now work on cache
- Removed arguments and environment variables from `Dockerfile`
