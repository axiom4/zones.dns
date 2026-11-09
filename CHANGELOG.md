# Changelog

## Unreleased
- Query log: the client filter is a text box with auto-complete over the distinct client IPs (most active first, at most 500; type an IP or a name), each shown with the FQDN of `DEFAULT_ZONE` whose A/AAAA record has that IP (also shown on the rows and in the query details). New `GET /api/logs/clients/` (`hours` optional) reads the hourly `client` counters, a few rows, not the log. IPv6 addresses are matched as text; with several names for one IP the shortest wins.
- DNS protocol conformance (RFC 1035, 2308, 4592, 6891): NXDOMAIN for blocked and suspicious names is no longer authoritative and carries an SOA (clients can cache it for `DNS_CACHE_NEG_TTL`); a static host's NODATA answer carries an SOA; a query with an EDNS OPT gets an OPT back, and the upstream cache key now includes EDNS, DO and CD (the cache refills by itself after the update); a UDP answer larger than 512 bytes, or than the size the client announced (at most 1232), is cut with TC=1 so the client retries over TCP; more than one question gives FORMERR, an opcode other than QUERY gives NOTIMP, a class other than IN gives REFUSED; a wildcard no longer covers a name that exists as an empty non-terminal. Restart the daemon.
- `manage.py import_asn`: nightly IP → ASN index built from ipverse/as-ip-blocks (BGP prefixes per ASN, CC0), used for the addresses that the ASN `.mmdb` lacks (about 1% of answers; they were filled by Team Cymru DNS lookups or stayed unknown). It streams the 17 MB archive without extracting it, flattens nested prefixes (the most specific wins) and writes a compact file (`ASN_INDEX`, 8 MB) that is searched in place and reopened by itself; if the download or the archive is broken the old index stays. `ASN_INDEX` (empty = off) and `ASN_IMPORT_URL`.
- Sign-in sessions last at most 2 hours (`SESSION_MAX_AGE`, 7200 s; absolute, not idle): the API token expires that long after the sign-in that issued it (the GUI returns to the sign-in page on the 401), and so does the Django admin session. Every sign-in issues a new token, so signing in on another device ends the user's older sessions.
- Query log partitioned by day on MySQL/MariaDB and PostgreSQL (`manage.py partition_querylog`, once; rebuilds the table, so run it at a quiet time and back up first): old days are dropped with `DROP PARTITION` / `DROP TABLE` instead of a huge `DELETE`, and `rundns` creates the next days' partitions every hour. The primary key becomes `(id, time)`. On PostgreSQL the table is replaced by a partitioned one (no default partition: the next 7 days must exist). SQLite is unchanged. The PostgreSQL path was written without a PostgreSQL server at hand: try it on a copy first.
- Statistics and geolocation read hourly counters (`StatCount`, `GeoStat`) kept up to date with every batch of log rows, instead of grouping the whole log: much faster on an external database. Windows over 2 hours start at the hour in which they begin; the per-minute view (up to 2 hours) still reads the log. Needs `manage.py migrate` (0019), then `manage.py rebuild_stats` once to count the existing log. Purging the log also purges the counters.
- Statistics: one scan instead of three for total, average and outcomes; the response is cached for 30 seconds.
- Fewer database round trips: geolocation cache saved with one `bulk_create` upsert instead of two queries per address; the daemon's reload reads both master switches in one query and records and hosts as plain values.
- Query log indexes on `name`, `(domain, time)` and `(outcome, time)`. Needs `manage.py migrate` (0018).

## 1.0.1 — 2026-11-08
- RFC 6303: reverse lookups (PTR) of private and special addresses (10/8, 172.16/12, 192.168/16, 100.64/10, 169.254/16, 127/8, `fc00::/7`, `fe80::/10`, `::1`) that no zone answers get NXDOMAIN from the daemon, with the `aa` flag and an SOA, and never go to the upstream (routers often answer SERVFAIL). `DNS_LOCAL_REVERSE=false` turns it off. A local reverse zone still answers first.
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
