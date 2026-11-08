# Changelog

## Unreleased
- Deleting a zone needs a second factor (authenticator code or passkey) from the already signed-in user, no password: step-up endpoints `/api/mfa/stepup/…` give a one-use grant (2 minutes, one zone) that `DELETE /api/zones/<id>/` requires in `X-MFA-Grant`. Users with no second factor are not asked.
- Zones can be switched off and on one by one (`enabled` flag; switch next to the zone name in the GUI, and in the Django admin): a disabled zone and its records are kept but not served, its names are answered as if the zone did not exist; the GUI shows its records as disabled and read-only. Needs `manage.py migrate` (0017).
- Master switch for the Public lists too (`GET`/`PATCH /api/blocked/public/`): off = the imported domains are kept but ignored and shown as disabled; the Personal blocks keep working. At once, no new migration beyond 0016.
- Master switch for the Personal blocks (GUI, top of the page; `GET`/`PATCH /api/blocked/personal/`): off = the blocks added by hand are kept but ignored, the imported public lists keep blocking. Takes effect at once. Needs `manage.py migrate` (0016).
- Personal blocks can be switched off and on (`enabled` flag, GUI switch and Django admin): a disabled block is kept but does not block. Needs `manage.py migrate` (0015).
- Internal zones are authoritative: a name missing from a zone gets NXDOMAIN, a name without that record type gets NODATA (empty NOERROR), both with `aa` and a generated SOA (RFC 2308) instead of going to the upstream; `SOA` queries at the zone apex are answered. **Behaviour change:** names under an internal zone that have no record are no longer forwarded; `DNS_AUTHORITATIVE=false` brings the forwarding back.
- A CNAME that points to a name in our own zones now also returns the target's records (e.g. `www CNAME @` answers with the apex A record).
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
