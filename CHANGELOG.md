# Changelog

## Unreleased
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
