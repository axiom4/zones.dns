# Changelog

## Unreleased
- Zone records can be sorted by type, host, IP / value (IPv4 numerically, then IPv6 and names) or TTL, ascending or descending.
- Statistics: the chart follows the chosen period (per minute for the last hour, per hour for 24 h, per day for 7 and 30 days: 7 and 30 bars, today included, days in the browser's time zone), with empty buckets shown as zero. The stats API takes an optional `since`. API: `per_hour` replaced by `series` + `step`.
- Static hosts (like `/etc/hosts`): exact names answered with fixed IPv4/IPv6 addresses before zones, blacklist and upstream; GUI page, API (`/api/hosts/`) and Django admin; loaded in the in-memory/Redis copy and refreshed on every change. Needs `manage.py migrate`.
- Prefetch: cached answers that are about to expire and still asked for are renewed in the background (`DNS_PREFETCH*`); cached TTLs now count down.
- Query log written in batches by a background thread (`DNS_LOG_FLUSH`, `DNS_LOG_QUEUE`): answers no longer wait for the database write. Needs `manage.py migrate`.
- Persistent database connections: the DNS daemon uses a fixed pool of worker threads (`DNS_WORKERS`) that keep their connection open, `DB_CONN_MAX_AGE` and connection health checks for the API.
- One persistent, shared Redis connection pool per process (`REDIS_POOL_SIZE`): the daemon no longer opens a connection per query.
- Zones, records and blacklist answers stay in the DNS daemon's memory until the data changes (change counter in the database and in Redis, `DNS_DATA_CHECK`, `DNS_DATA_TTL`; with Redis a change shows at once and a restart is warm): fewer database reads per query. Needs `manage.py migrate`.
- Several upstream resolvers with failover (`UPSTREAM_DNS=a,b`), and stale answers served from the cache when all are down (`DNS_STALE_TTL`).

## 1.0.0 — 2026-11-07

First release of Zones.dns (backend and frontend share the version).

### DNS daemon
- Internal zones (forward and reverse) served from the database; everything else forwarded to `UPSTREAM_DNS`, with an upstream answer cache (Redis or in-process).
- Records of 13 types, wildcards, enable/disable, notes, zone file import/export, automatic PTR records.
- Query log with outcome, resolution path and answers; blacklist (personal blocks and imported public lists); suspicious-query filter (tunnelling, DGA, ANY/AXFR, subdomain scans).

### GUI (Angular 22)
- Zones, Blacklist, Query log, Geolocation (map), Domain audit, Statistics and Security pages; guided record form; English interface.
- Responsive layout for phones, tablets and landscape; lazy-loaded routes.

### Security
- Encrypted sign-in and second-factor steps (NaCl `crypto_box`, fresh server key at every start).
- Two-step sign-in with authenticator app (TOTP) or passkey; mandatory by default.
- Django admin opened only from the GUI, for superusers, with a one-use ticket.
- Weak `SECRET_KEY` refused with `DEBUG=false`.

### Operations
- API described in OpenAPI; generated Angular client.
- nginx virtual host (HTTPS, HTTP/2, HTTP/3).
- Commands: `rundns`, `import_blocklist`, `scan_trackers`, `mfa_reset`.

Licence: BSD 3-Clause.
