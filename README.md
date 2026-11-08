# Zones.dns

DNS daemon (Python/dnslib) + API (Django 6.1.3 / DRF 3.18.3) + GUI (Angular 22).
Zones and records live in the database; the daemon reads them on every query, so changes made in the GUI take effect at once.
Names the internal zones cannot answer are forwarded to `UPSTREAM_DNS` (default 1.1.1.1; several resolvers, comma separated, are tried in order).

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
| **Zones** | Forward and reverse zones (from a CIDR), records with a guided form for 13 types (A, AAAA, CNAME, MX, TXT, NS, PTR, SRV, NAPTR, HTTPS, CAA, SSHFP, TLSA), wildcards, enable/disable, notes, bulk actions, zone file import/export, automatic PTR records. `DEFAULT_ZONE` picks the zone opened by default. |
| **Blacklist** | *Personal blocks* (domains you block by hand, editable) and *Public lists* (imported, read-only, searchable). Blocked domains and their subdomains answer NXDOMAIN. |
| **Query log** | Search and filters, grouping by domain (with subdomains), the full answer of every query, one-click blocking, a button to purge old entries. |
| **Geolocation** | Where DNS answers point: countries, networks, cities and a map (see below). |
| **Domain audit** | Public information about a domain: DNS, DNSSEC, mail (SPF/DMARC/DKIM/MTA-STS), RDAP, TLS, web headers, subdomains; every test has its own "Output". |
| **Statistics** | Queries per hour, most requested domains and most active clients, query types, timings. |
| **Security** | The user's second factors: authenticator app and passkeys. |

The menu also has **Django admin ↗** (superusers only), which opens the admin: zones, records, blacklist (*Personal blocks* and *Public lists* sections), log, GeoIP cache and MFA factors.

The interface adapts to phones (portrait and landscape) and tablets: below 1100 px the sidebar becomes a top bar.
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
| `REDIS_URL`, `DNS_CACHE` (+ TTLs) | Cache. |
| `GEOIP_CITY_DB`, `GEOIP_ASN_DB`, `GEOIP_ONLINE_FALLBACK` | Geolocation. |
| `BEHIND_PROXY`, `CSRF_TRUSTED_ORIGINS` | Behind nginx with https. |

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

**Upstream failover.** `UPSTREAM_DNS=192.168.1.254,1.1.1.1` tries the resolvers in order: after `DNS_UPSTREAM_TIMEOUT` seconds (2) without an answer, or a SERVFAIL, it asks the next. A resolver that did not answer at all is skipped for `DNS_UPSTREAM_DOWN` seconds (30), so a dead one does not slow every query. If **all** are down, an answer that expired up to `DNS_STALE_TTL` seconds ago (86400; 0 = never) is served from the cache with a TTL of at most 30 s; the Query log shows it as `stale cache (upstream down)`. A name never asked before gets SERVFAIL. With `REDIS_URL` set, the sign-in replay protection also uses Redis.

## Production deployment

The full, step-by-step guide is in **[INSTALL.md](INSTALL.md)**: prerequisites, TLS, PostgreSQL or MySQL/MariaDB, Redis, nginx (HTTP/3), supervisor, port 53 without root, firewall, verification, client setup, backup, hardening, updates and troubleshooting.

Summary: gunicorn (**one worker only**, the sign-in key lives in process memory) behind nginx, `manage.py rundns` as a second supervisor program, `DEBUG=false`, a long `SECRET_KEY`, `BEHIND_PROXY=true`, `DATABASE_URL` and `REDIS_URL` set, then `migrate` and `collectstatic`. The virtual host is `deploy/nginx/dns.example.lan`.

## Tests

The project has no automated tests. The features were tried by hand (Django test client, `curl`, headless Chrome, also with a virtual authenticator for passkeys and phone and tablet emulation).

## Licence

Code released under the **BSD 3-Clause** licence (see [LICENSE](LICENSE)). The libraries used keep their own licences. The DB-IP GeoIP databases, downloaded separately, are under CC BY 4.0 (credit "IP Geolocation by DB-IP") and are not part of the repository.
