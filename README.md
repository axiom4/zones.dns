# Zones.dns

DNS daemon (Python/dnslib) + API (Django 6.1.3 / DRF 3.18.3) + GUI (Angular 22).
Zones and records live in the database; the daemon keeps a copy in memory and reloads it when the data changes, so changes made in the GUI take effect at once (within a second without Redis).
Internal zones are authoritative (RFC 1034/2308): inside a zone, a name that does not exist gets `NXDOMAIN` and a name without a record of the asked type gets an empty `NOERROR` answer, both with the `aa` flag and a generated SOA in the authority section; a CNAME to a name in another internal zone also returns that name's records. Only names **outside** every internal zone are forwarded to `UPSTREAM_DNS` (with `DNS_AUTHORITATIVE=false` the missing names of an internal zone are forwarded too, for a zone that overrides only some names of a real domain) (default 1.1.1.1; several resolvers, comma separated, are tried in order).

## Quick start (development)

```sh
python3 -m venv .venv && .venv/bin/pip install -r backend/requirements.txt
cd backend
cp .env.example .env                                   # then adjust the values (see "Configuration")
../.venv/bin/python manage.py migrate
../.venv/bin/python manage.py createsuperuser          # superuser and staff: needed for the GUI and the admin
../.venv/bin/python manage.py runserver 8000           # API
../.venv/bin/python manage.py rundns --port 5353       # DNS (port 53 needs root)
cd ../frontend && npm install && npx ng serve          # GUI at http://localhost:4200
dig @127.0.0.1 -p 5353 www.corp.lan
```

`ng serve` forwards `/api`, `/admin` and `/static` to the backend at `127.0.0.1:8000` (`frontend/proxy.conf.json`).
To use the GUI a user needs the **staff** flag; the Django admin is reserved to **superusers**.

## What is in the GUI

| Section | What it does |
|---|---|
| **Zones** | Forward and reverse zones (from a CIDR), records with a guided form for 13 types (A, AAAA, CNAME, MX, TXT, NS, PTR, SRV, NAPTR, HTTPS, CAA, SSHFP, TLSA), wildcards, enable/disable, notes, bulk actions, zone file import/export, automatic PTR records. `DEFAULT_ZONE` picks the zone opened by default. Record list sortable by type, host, IP / value or TTL (default: by IP; in a reverse zone "IP" is the full address and "host" the PTR name). Names in a value (CNAME, MX, NS, SRV, PTR) outside the zone need the final dot: `axiom4.net.`, otherwise they are relative to the zone. |
| **Hosts** | Static host names, like `/etc/hosts`: a name is answered with the IPv4/IPv6 address you set, whatever the real DNS says. Several addresses per name, TTL, note, enable/disable. |
| **Blacklist** | *Personal blocks* (domains you block by hand, editable) and *Public lists* (imported, read-only, searchable). Blocked domains and their subdomains answer NXDOMAIN. |
| **Query log** | Search and filters, grouping by domain (with subdomains), the full answer of every query, one-click blocking, a button to purge old entries. |
| **Geolocation** | Where DNS answers point: countries, networks, cities and a map (see below). |
| **Domain audit** | Public information about a domain: DNS, DNSSEC, mail (SPF/DMARC/DKIM/MTA-STS), RDAP, TLS, web headers, subdomains; every test has its own "Output". |
| **Statistics** | Queries over time (one bar per minute, hour or day, following the chosen period: 7 and 30 days are whole calendar days, today included), most requested domains and most active clients, query types, timings. |
| **Security** | The user's second factors: authenticator app and passkeys. |

The menu also has **Django admin ↗** (superusers only), which opens the admin: zones, records, blacklist (*Personal blocks* and *Public lists* sections), log, GeoIP cache and MFA factors.

The interface adapts to phones (portrait and landscape) and tablets: below 1100 px the sidebar becomes a top bar.
The Angular sources in `frontend/src/app/` have one folder per component (`zone-page/zone-page.ts` + `zone-page.html`), `services/` for injectable classes and `lib/` for plain helpers.
The API is described in OpenAPI (`/api/schema/`, docs at `/api/docs/`) and the Angular client is generated from it: after any API change run `npm run api:gen` in `frontend/`.
The interface language is English.

## Configuration (`backend/.env`)

Every variable, with example values and comments, is in `backend/.env.example`. The main ones:

| Variable | Meaning |
|---|---|
| `SECRET_KEY` | Required and long (≥ 50 characters) with `DEBUG=false`: the server will not start with a weak key. Generate one: `python -c "from django.core.management.utils import get_random_secret_key as g; print(g())"`. It signs sessions and sign-in tickets: if it is known, the admin can be forged. |
| `DEBUG`, `ALLOWED_HOSTS` | `DEBUG=false` and explicit hosts in production. |
| `DATABASE_URL` | Empty = SQLite; otherwise `postgres://…` or `mysql://…`. |
| `UPSTREAM_DNS`, `QUERY_LOG_DAYS`, `DEFAULT_ZONE` | External resolver(s), days of log to keep, zone opened by default. |
| `LOGIN_ENCRYPTION` | `off` / `optional` / `required` (see "Encrypted sign-in"). |
| `MFA_REQUIRED`, `MFA_ISSUER`, `WEBAUTHN_RP_ID`, `WEBAUTHN_ORIGINS` | Second factor and passkeys. |
| `GUI_URL` | Where `/admin/login/` sends people (the GUI). |
| `SUSPICIOUS_MODE`, `SUSPICIOUS_ALLOW` (+ thresholds) | Suspicious queries. |
| `DNS_AUTHORITATIVE` | `true` (default): a name or record type missing from an internal zone gets NXDOMAIN/NODATA. `false`: it is forwarded to the upstream (a zone that overrides only some names of a real domain). |
| `TIME_ZONE` | Zone the Django admin shows times in (the GUI uses the browser's). MySQL/MariaDB then needs the time zone tables, see below. |
| `REDIS_URL`, `DNS_CACHE` (+ TTLs) | Cache. |
| `GEOIP_CITY_DB`, `GEOIP_ASN_DB`, `GEOIP_ONLINE_FALLBACK` | Geolocation. |
| `BEHIND_PROXY`, `CSRF_TRUSTED_ORIGINS` | Behind nginx with https. |

**MySQL/MariaDB and `TIME_ZONE`.** With a `TIME_ZONE` other than UTC the admin's date filters (e.g. GeoIP cache) fail with "Database returned an invalid datetime value" until the database has its time zone tables. Load them once: `mariadb-tzinfo-to-sql /usr/share/zoneinfo | sudo mariadb -u root mysql` (MySQL: `mysql_tzinfo_to_sql`). Check: `SELECT CONVERT_TZ('2026-11-08 12:00:00','UTC','Europe/Rome')` must not be `NULL`.

`python manage.py check --deploy` with `BEHIND_PROXY=true` reports nothing except HSTS for subdomains and preloading (choices that are hard to undo, not enabled).

## Encrypted sign-in (asymmetric keys)

The sign-in packet (user, password, time and a one-time code) is encrypted in the browser with the server's **public** key
(Curve25519, NaCl `crypto_box`); the server opens it with its **private** key and answers, always encrypted, only to that client.
**All the second-factor steps too** (ticket, codes, passkey data, the app secret) travel through the same encrypted channel, on `POST /api/mfa/encrypted/`.

The server makes a **new key pair at every start**, keeps it in memory only (no file, no `.env`) and publishes the public half at
`GET /api/login-key/`. The frontend downloads it before every step: no key to configure or rebuild.
If the server restarts between the download and the send, the frontend downloads the key again and retries by itself.

`LOGIN_ENCRYPTION`: `off` (sign-in and second factor in clear), `optional` (both), `required` (plain requests are refused; **recommended**).

Limits: the key lives in the memory of a single process, so run the server as one process (several workers would each have a different key).
The key is downloaded from an unauthenticated endpoint: it protects against passive eavesdropping, not against someone who can alter the responses (use HTTPS).

## Two-step sign-in (MFA) and the admin

After the password a second factor is required: a code from an authenticator app (TOTP) or a **passkey**. With `MFA_REQUIRED=true` whoever has none sets one up at the first sign-in; afterwards they manage them in the **Security** page (the last factor cannot be removed while MFA is mandatory). Five wrong codes lock attempts for five minutes; a code that was already used does not work twice.

```sh
python manage.py mfa_reset <user>   # lost phone or key: the user starts the setup again
```

Passkeys: set `WEBAUTHN_RP_ID` (the GUI host, no port) and `WEBAUTHN_ORIGINS` (full addresses); they need https, except on `localhost`.

The **Django admin has no password sign-in of its own**: it is opened from the GUI with **Django admin ↗**, for superusers only. After password and second factor (all encrypted) the GUI asks the server for a one-use ticket valid for 60 seconds and posts it to `/admin/sso/`, which opens the session. `/admin/login/` sends people to the GUI (`GUI_URL`), and an admin session obtained any other way, or by a non-superuser, is closed. In production the GUI and `/admin` must be on the same address.

## Suspicious queries

The resolver checks names **before** forwarding them (internal zones are never touched). `SUSPICIOUS_MODE`: `off`, `log` (flag them in the log but forward them) or `block` (NXDOMAIN). Rules:

- types `ANY`, `AXFR`, `IXFR`;
- a name over 120 characters or a label over 50;
- random-looking labels (high entropy: tunnelling, DGA);
- more than 40 distinct subdomains of the same domain, from the same client, within 60 s.

Thresholds are in `.env.example`. Add the legitimate main domains that get flagged (for example CDNs with hexadecimal names) to `SUSPICIOUS_ALLOW`. Start with `log`, check for false positives in the log, then switch to `block`.

## Blocklists

```sh
python manage.py import_blocklist              # StevenBlack/hosts: ads and malware (default)
python manage.py import_blocklist <url|file>   # another list: hosts format or one domain per line
python manage.py scan_trackers [--apply]       # heuristic: redirect + cookie (see below)
```

`import_blocklist` replaces the imported entries on every run (update it from cron); entries added by hand are left alone. Imported entries show in **Blacklist → Public lists** (read-only, searchable) and are deleted from the admin; they come back at the next import.

`scan_trackers` probes over HTTP (public IPs only, ports 80/443) the domains forwarded in the log and matches those that redirect to a different main domain **and** set persistent cookies, but only if the chain ends on something that is not an HTML page (a site such as `gmail.com` is not touched). It is cautious and finds few real trackers: without `--apply` it only lists them. For serious blocking use `import_blocklist`.

## Geolocation and map

The **Geolocation** page counts all the answered queries of the chosen period and shows country, network and, with a local database, cities on the map.
By default country and network come from DNS (Team Cymru) and are cached; for **cities** and to work **fully offline** use a local GeoIP database in MaxMind format (`.mmdb`):

- **DB-IP Lite** (CC BY 4.0, credit "IP Geolocation by DB-IP"; no account), published on GitHub by `sapics/ip-location-db`:
  ```sh
  mkdir -p backend/geoip-data && cd backend/geoip-data
  B=https://github.com/sapics/ip-location-db/releases/download/latest
  for f in dbip-asn.mmdb dbip-city-ipv4.mmdb dbip-city-ipv6.mmdb; do curl -fL --proto '=https' -o $f $B/$f; done
  ```
  (about 134 MB; the city database has one file for IPv4 and one for IPv6, listed separated by a comma). It is updated every month: run the `curl` commands again.
- or **GeoLite2** City and ASN (MaxMind, free account): https://dev.maxmind.com/geoip/geolite2-free-geolocation-data

```sh
# backend/.env  (absolute paths)
GEOIP_CITY_DB=/path/backend/geoip-data/dbip-city-ipv4.mmdb,/path/backend/geoip-data/dbip-city-ipv6.mmdb
GEOIP_ASN_DB=/path/backend/geoip-data/dbip-asn.mmdb      # optional: the network (AS) without asking DNS
GEOIP_ONLINE_FALLBACK=false                               # optional: no DNS queries for geolocation
```

The files are re-read by themselves when you replace them. Accuracy is that of the database: the city is an approximation (CDNs and cloud servers often show up in another city).

## Redis cache

```
REDIS_URL=redis://127.0.0.1:6379/0   # in backend/.env; empty = in-process memory cache
DNS_CACHE=true                       # upstream answers cached for their TTL
```

The DNS daemon remembers upstream answers (at most `DNS_CACHE_MAX_TTL`, 300 s; NXDOMAIN and empty answers `DNS_CACHE_NEG_TTL`, 60 s; errors never). The blacklist, suspicious-query checks and internal zones are applied **before** the cache. If Redis does not answer, the daemon asks the upstream directly.

**Persistent connections.** Each process keeps one pool of Redis connections (`REDIS_POOL_SIZE`, 20) that every thread shares; connections stay open and are reused (TCP keep-alive, a ping before reuse after 30 s idle, automatic reconnect after a Redis restart). `rundns` opens a few at start. Calls time out after 1 s, so a stuck Redis cannot stall DNS answers.

**Zones, records and blacklist in memory and Redis.** Zones, enabled records and blacklist answers are kept until the data changes, so most queries read no database at all (only the log write remains). Every change (GUI, admin, `import_blocklist`) raises a counter (`DataVersion`).
- **With `REDIS_URL`:** the counter, the data and the blacklist answers are also stored in Redis (`data:<n>`, `bl:<n>:<name>`). The daemon checks the counter on every query, so a change shows **at once**, a restarted daemon starts warm without reading the database, and several daemons share one copy. If Redis is down the daemon falls back to the database.
- **Without Redis:** the daemon keeps the copy in its own memory and looks at the counter in the database once per `DNS_DATA_CHECK` seconds (1).

As a safety net a copy older than `DNS_DATA_TTL` seconds (300) is reloaded anyway, which covers changes made behind the app's back (raw SQL, a restored backup). Run `manage.py migrate` after updating: the counter is a new table.

**Static hosts.** A name in **Hosts** is answered with your address and never reaches the zones, the blacklist or the upstream: `A` queries get the IPv4 addresses, `AAAA` the IPv6 ones, and any other type (HTTPS, MX, …) an empty answer, so nothing real leaks through (like a hosts file). Matching is exact (no wildcards, no subdomains); put several rows for several addresses. The hosts are loaded with zones and records into the in-memory/Redis copy (`snap:<n>` in Redis) and every add, edit, enable/disable or delete raises the same change counter, so the daemon uses it at once (within `DNS_DATA_CHECK` seconds without Redis). A name with only an IPv6 row answers `A` with an empty answer. The Query log shows these answers as `local` / `static host`.

**Persistent database connections.** Connections to MySQL/MariaDB or PostgreSQL stay open and are reused (`DB_CONN_MAX_AGE`, 600 s, with a ping before reuse, so one the database dropped is replaced). The DNS daemon answers on a fixed set of worker threads (`DNS_WORKERS`, 16 per protocol) instead of a thread per query, and each worker keeps its connection: the workers are the pool, and `rundns` opens a few at start. The API does the same per gunicorn thread. Set the database's `max_connections` above `DNS_WORKERS * 2` plus the 8 gunicorn threads and a few for management commands. Queries beyond `DNS_WORKERS * 8` waiting are dropped (flood protection).

**Prefetch.** Each cached answer remembers when it expires. The TTL a client receives counts down, so it never keeps a record longer than the origin allowed. When a cached answer is asked for again with less than `DNS_PREFETCH_AT` (20%) of its TTL left, the daemon answers from the cache and renews it from the upstream in the background (`DNS_PREFETCH_WORKERS` threads, one renewal per name at a time, shared through Redis when it is used), so names that people keep asking for never wait for the upstream. Names nobody asks for again just expire. If every upstream is down the old entry is kept until it expires (and then the stale copy applies). `DNS_PREFETCH=false` turns it off.

**Query log in batches.** The daemon answers first and saves the log afterwards: rows wait in a queue and one thread writes them with a single INSERT every `DNS_LOG_FLUSH` seconds (1). The log therefore shows a query up to a second later, and a sudden crash can lose the last second of rows (a normal stop saves them). If the database cannot keep up, up to `DNS_LOG_QUEUE` rows (50000) wait and newer ones are dropped, so DNS answers never slow down. `DNS_LOG_FLUSH=0` writes each row before answering. Run `manage.py migrate` after updating (the log's `time` is now set when the query arrives).

**Upstream failover.** `UPSTREAM_DNS=192.168.1.254,1.1.1.1` tries the resolvers in order: after `DNS_UPSTREAM_TIMEOUT` seconds (2) without an answer, or a SERVFAIL, it asks the next. A resolver that did not answer at all is skipped for `DNS_UPSTREAM_DOWN` seconds (30), so a dead one does not slow every query. If **all** are down, an answer that expired up to `DNS_STALE_TTL` seconds ago (86400; 0 = never) is served from the cache with a TTL of at most 30 s; the Query log shows it as `stale cache (upstream down)`. A name never asked before gets SERVFAIL. With `REDIS_URL` set, the sign-in replay protection also uses Redis.

## Production deployment

The full, step-by-step guide is in **[INSTALL.md](INSTALL.md)**: prerequisites, TLS, PostgreSQL or MySQL/MariaDB, Redis, nginx (HTTP/3), supervisor, port 53 without root, firewall, verification, client setup, backup, hardening, updates and troubleshooting.

Summary: gunicorn (**one worker only**, the sign-in key lives in process memory) behind nginx, `manage.py rundns` as a second supervisor program, `DEBUG=false`, a long `SECRET_KEY`, `BEHIND_PROXY=true`, `DATABASE_URL` and `REDIS_URL` set, then `migrate` and `collectstatic`. The virtual host is `deploy/nginx/dns.example.lan`.

## Tests

Run `python manage.py test zones` in `backend/` (resolver: CNAME chasing, NXDOMAIN/NODATA/SOA, `DNS_AUTHORITATIVE`). The rest was tried by hand (Django test client, `curl`, headless Chrome, also with a virtual authenticator for passkeys and phone and tablet emulation).

## Licence

Code released under the **BSD 3-Clause** licence (see [LICENSE](LICENSE)). The libraries used keep their own licences. The DB-IP GeoIP databases, downloaded separately, are under CC BY 4.0 (credit "IP Geolocation by DB-IP") and are not part of the repository.
