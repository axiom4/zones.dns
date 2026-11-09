# Installing Zones.dns in production

Complete guide for a server install: PostgreSQL or MySQL/MariaDB, Redis, nginx, supervisor. Commands are for Debian/Ubuntu; adjust package names and paths for other systems. For a development setup see the README.

## 1. Before you start

**Server.** One Linux host (physical, VM or container) with a fixed IP address, root/sudo access, and these packages:

| Need | Notes |
|---|---|
| Python 3.12 or newer, `venv`, `pip` | Django 6.1 needs a recent Python (check the [Django docs](https://docs.djangoproject.com/en/6.1/faq/install/)). |
| nginx ≥ 1.25 with `http_v3` | Only for HTTP/3; older nginx works if you remove the `quic`/`http3` lines from the virtual host. Check: `nginx -V 2>&1 \| grep http_v3`. |
| PostgreSQL **or** MariaDB/MySQL | Local or on another host. SQLite works but is for development only. |
| Redis | Upstream DNS cache, sign-in replay and lockout counters. Optional, but recommended. |
| supervisor | Keeps the API and the DNS daemon running. |
| Node.js + npm | Only to build the GUI; can be another machine. Use a Node version supported by Angular 22. |

**Decide first:**

- the **host name** of the GUI (for example `dns.example.com`): it goes in `ALLOWED_HOSTS`, `CSRF_TRUSTED_ORIGINS`, `GUI_URL`, `WEBAUTHN_RP_ID`, `WEBAUTHN_ORIGINS`, the TLS certificate and the nginx `server_name`. Passkeys are bound to this name: changing it later invalidates them;
- the **IP address** the DNS daemon will listen on, and which networks may query it;
- the **upstream resolvers** (`UPSTREAM_DNS`, default `1.1.1.1`): list at least two, comma separated, so the network keeps resolving when one is down.

Both gunicorn and `rundns` are single instances: the sign-in key lives in the memory of one process (see "Encrypted sign-in" in the README), and `rundns` also purges the old log once an hour.

Paths below: code in `/opt/dns/app`, virtualenv `/opt/dns/.venv`, user `dns`, host `dns.example.com`, server IP `192.0.2.10`.

## 2. TLS certificate and key

https is required (passkeys and secure cookies do not work over plain http). nginx needs two files, named in the virtual host (`deploy/nginx/dns.example.lan`, lines `ssl_certificate` and `ssl_certificate_key`):

| File | Content | Permissions |
|---|---|---|
| `/etc/ssl/certs/dns.example.com.pem` | certificate (with the intermediate certificates, if any) | `644`, root |
| `/etc/ssl/private/dns.example.com.key` | **private key**: never copy it elsewhere, never commit it | `600`, root |

Edit both paths in the virtual host if you keep the files somewhere else. nginx reads them as root at start, so the `dns` user does not need access. Pick **A** or **B**.

### A. Public name: Let's Encrypt

```sh
sudo apt install certbot
sudo mkdir -p /var/www/html
sudo certbot certonly --webroot -w /var/www/html -d dns.example.com --deploy-hook "systemctl reload nginx"
```

The name must resolve to this server and port 80 must be reachable from the internet (use `--standalone` instead of `--webroot` if nginx is not serving the site yet, with port 80 free). Certbot writes the files to `/etc/letsencrypt/live/dns.example.com/`: set in the virtual host

```
ssl_certificate     /etc/letsencrypt/live/dns.example.com/fullchain.pem;
ssl_certificate_key /etc/letsencrypt/live/dns.example.com/privkey.pem;
```

Certbot renews by itself (systemd timer); check with `sudo certbot renew --dry-run`.

### B. Internal name (`.lan`, `.home.arpa`, private IPs): your own CA

A public CA cannot issue certificates for these names. Create a small CA once, then a server certificate signed by it (run on a safe machine; the server only receives the certificate and its key):

```sh
mkdir tls && cd tls
# 1. the CA (10 years). ca.key is the most sensitive file: keep it offline, not on the server.
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 3650 \
  -keyout ca.key -out ca.pem -subj "/CN=Zones.dns internal CA" \
  -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign"

# 2. the server key and request: use the exact host name people type in the browser
openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
  -keyout server.key -out server.csr -subj "/CN=dns.example.com"

# 3. sign it. subjectAltName is mandatory: browsers ignore the CN. Add every name/IP you use.
printf "subjectAltName=DNS:dns.example.com,IP:192.0.2.10\nbasicConstraints=CA:FALSE\nkeyUsage=digitalSignature\nextendedKeyUsage=serverAuth\n" > san.ext
openssl x509 -req -in server.csr -CA ca.pem -CAkey ca.key -CAcreateserial -days 397 -extfile san.ext -out server.pem

openssl verify -CAfile ca.pem server.pem        # server.pem: OK
```

Install on the server:

```sh
sudo install -m 644 -o root server.pem /etc/ssl/certs/dns.example.com.pem
sudo install -m 600 -o root server.key /etc/ssl/private/dns.example.com.key
shred -u server.key server.csr                   # remove the copies you do not need
```

Renew before it expires (397 days is the longest browsers accept): repeat steps 2–3 and the install commands, then `sudo systemctl reload nginx`. Check the expiry: `openssl x509 -in /etc/ssl/certs/dns.example.com.pem -noout -enddate`.

**Trust the CA on every client** (`ca.pem` only, never `ca.key`), otherwise browsers refuse the site and passkeys do not work:

- Debian/Ubuntu: `sudo cp ca.pem /usr/local/share/ca-certificates/zones-ca.crt && sudo update-ca-certificates`
- macOS: `sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain ca.pem`
- Windows (administrator): `certutil -addstore -f Root ca.pem`
- Firefox has its own store (Settings → Certificates → Authorities → Import); iOS and Android: install the file as a profile/certificate and enable full trust.

### Check the result

```sh
sudo openssl x509 -in /etc/ssl/certs/dns.example.com.pem -noout -subject -enddate -ext subjectAltName
sudo nginx -t && sudo systemctl reload nginx
openssl s_client -connect dns.example.com:443 -servername dns.example.com </dev/null 2>/dev/null | grep "Verify return"
```

The last line must say `Verify return code: 0 (ok)` (add `-CAfile ca.pem` when using your own CA).

## 3. System user and code

```sh
sudo useradd --system --create-home --home-dir /opt/dns --shell /usr/sbin/nologin dns
sudo -u dns git clone https://github.com/axiom4/zones.dns.git /opt/dns/app            # or unpack the release archives from release/
sudo -u dns python3 -m venv /opt/dns/.venv
sudo -u dns /opt/dns/.venv/bin/pip install -r /opt/dns/app/backend/requirements.txt gunicorn
```

## 4. Database

Pick one, create the database and a dedicated user, install the matching Python driver (neither is in `requirements.txt`) and set `DATABASE_URL`.

**PostgreSQL**

```sh
sudo apt install postgresql libpq-dev
sudo -u postgres psql <<'SQL'
CREATE USER dns WITH PASSWORD 'change-me';
CREATE DATABASE dns OWNER dns ENCODING 'UTF8';
SQL
sudo -u dns /opt/dns/.venv/bin/pip install "psycopg[binary]"
```
```
DATABASE_URL=postgres://dns:change-me@127.0.0.1:5432/dns
```

**MySQL / MariaDB**

```sh
sudo apt install mariadb-server libmariadb-dev pkg-config build-essential     # MySQL: default-libmysqlclient-dev
sudo mysql <<'SQL'
CREATE DATABASE dns CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER 'dns'@'127.0.0.1' IDENTIFIED BY 'change-me';
GRANT ALL PRIVILEGES ON dns.* TO 'dns'@'127.0.0.1';
SQL
sudo -u dns /opt/dns/.venv/bin/pip install mysqlclient
```
```
DATABASE_URL=mysql://dns:change-me@127.0.0.1:3306/dns
```
With a `TIME_ZONE` other than UTC, load the time zone tables once, or the admin's date filters fail ("Database returned an invalid datetime value"):
```
mariadb-tzinfo-to-sql /usr/share/zoneinfo | sudo mariadb -u root mysql     # MySQL: mysql_tzinfo_to_sql
```

Percent-encode special characters in the password inside the URL (`@` → `%40`, `/` → `%2F`, `:` → `%3A`). Keep the database on `127.0.0.1` or a private network; if it is on another host, use TLS and allow only the app server. Supported database versions are those of Django 6.1 ([docs](https://docs.djangoproject.com/en/6.1/ref/databases/)). Back it up (`pg_dump` / `mariadb-dump`): zones, records, users and second factors live only there.

## 5. Redis

```sh
sudo apt install redis-server
```
In `/etc/redis/redis.conf`:
```
bind 127.0.0.1 ::1
requirepass change-me
maxmemory 256mb
maxmemory-policy allkeys-lru
```
```sh
sudo systemctl restart redis-server
```
```
REDIS_URL=redis://:change-me@127.0.0.1:6379/0
```
Redis holds the upstream DNS cache and the sign-in replay and lockout counters. Never expose it to the network. Under memory pressure `allkeys-lru` can evict a lockout counter, so give it enough memory. If Redis is down, the daemon asks the upstream directly.

## 6. Configuration

`/opt/dns/app/backend/.env` (start from `.env.example`; `chmod 600`, owner `dns`):

```
SECRET_KEY=<at least 50 random characters>
DEBUG=false
ALLOWED_HOSTS=dns.example.com
DATABASE_URL=...                      # step 4
REDIS_URL=...                         # step 5
BEHIND_PROXY=true                     # https, HSTS, secure cookies
CSRF_TRUSTED_ORIGINS=https://dns.example.com
GUI_URL=https://dns.example.com/
WEBAUTHN_RP_ID=dns.example.com
WEBAUTHN_ORIGINS=https://dns.example.com
LOGIN_ENCRYPTION=required
```

Then, once and after every update:

```sh
cd /opt/dns/app/backend
sudo -u dns ../../.venv/bin/python manage.py migrate
sudo -u dns ../../.venv/bin/python manage.py collectstatic --noinput
sudo -u dns ../../.venv/bin/python manage.py check --deploy
sudo -u dns ../../.venv/bin/python manage.py createsuperuser        # first install only
```

## 7. Frontend build and nginx

```sh
cd /opt/dns/app/frontend && npm ci && npx ng build        # -> dist/frontend/browser
sudo mkdir -p /var/www/dns
sudo rsync -a --delete dist/frontend/browser/ /var/www/dns/frontend/
sudo rsync -a --delete ../backend/staticfiles/ /var/www/dns/static/
sudo cp ../deploy/nginx/dns.example.lan /etc/nginx/sites-available/dns.example.com    # edit server_name (twice) and ssl_* paths
sudo ln -s /etc/nginx/sites-available/dns.example.com /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx
```

The virtual host (`deploy/nginx/dns.example.lan`, steps in the comments at the top) gives you:

- the static GUI with a fallback for the Angular routes; `/api/` and `/admin/` to gunicorn; `/static/` for the admin;
- https with HSTS, **HTTP/3 (QUIC)**, HTTP/2 and HTTP/1.1 on the same port (needs nginx ≥ 1.25 with `http_v3` and UDP port 443 open);
- request limits on sign-in and second factor; long caching only for hashed files.

The Node build can be done on another machine: only the `dist/frontend/browser` folder is needed on the server.

## 8. Supervisor

```sh
sudo apt install supervisor
```

`/etc/supervisor/conf.d/dns.conf` (on RHEL-like systems: `/etc/supervisord.d/dns.ini`):

```ini
[program:dns-api]
directory=/opt/dns/app/backend
command=/opt/dns/.venv/bin/gunicorn dnsadmin.wsgi -b 127.0.0.1:8000 --workers 1 --threads 8 --access-logfile -
user=dns
autostart=true
autorestart=true
stopasgroup=true
stdout_logfile=/var/log/supervisor/dns-api.log
stderr_logfile=/var/log/supervisor/dns-api.err.log

[program:dns-daemon]
directory=/opt/dns/app/backend
command=/opt/dns/.venv/bin/python manage.py rundns --address 0.0.0.0 --port 53
user=dns
autostart=true
autorestart=true
stopasgroup=true
stdout_logfile=/var/log/supervisor/dns-daemon.log
stderr_logfile=/var/log/supervisor/dns-daemon.err.log

[group:dns]
programs=dns-api,dns-daemon
```

```sh
sudo supervisorctl reread && sudo supervisorctl update
sudo supervisorctl status
```

**Port 53 without root.** `rundns` should not run as root. Give the Python binary the permission to bind low ports (it must be the real file, not the venv symlink, and the permission is lost when Python is upgraded):

```sh
sudo setcap cap_net_bind_service=+ep "$(readlink -f /opt/dns/.venv/bin/python)"
```

Alternative: run `rundns` on `5353` and redirect port 53 to it with nftables or iptables.

**Address already in use.** On Ubuntu `systemd-resolved` listens on `127.0.0.53:53`. Bind `rundns` to the server's own address (`--address 192.0.2.10`) or disable the stub (`DNSStubListener=no` in `/etc/systemd/resolved.conf`). Do not leave `--address 0.0.0.0` on a server that is reachable from the internet: an open resolver is abused for DDoS amplification. Firewall port 53 to your own networks.

## 9. Firewall

Open `80/tcp`, `443/tcp`, `443/udp` (HTTP/3) and `53/udp` + `53/tcp` (only for your clients). Keep `8000`, the database and Redis closed to the outside.

## 10. Verify the installation

```sh
sudo supervisorctl status                                   # dns:dns-api and dns:dns-daemon RUNNING
curl -sI https://dns.example.com/ | head -1                 # HTTP/2 200
curl -s https://dns.example.com/api/login-key/               # {"key": "..."}  (public key, new after each API restart)
dig @192.0.2.10 example.com                                 # forwarded upstream: NOERROR
dig @192.0.2.10 www.corp.lan                                # an internal zone you created: your record
sudo -u dns /opt/dns/.venv/bin/python /opt/dns/app/backend/manage.py check --deploy    # no warnings except HSTS subdomains/preload
```

Then open the GUI, sign in with the superuser and set up the second factor (authenticator app or passkey) when asked. Create a zone, query it with `dig`, and check the query shows in **Query log**.

## 11. Update

```sh
cd /opt/dns/app && sudo -u dns git pull
sudo -u dns /opt/dns/.venv/bin/pip install -r backend/requirements.txt
cd backend
sudo -u dns ../../.venv/bin/python manage.py migrate
sudo -u dns ../../.venv/bin/python manage.py rebuild_stats      # only when updating from a version without the hourly statistics counters
sudo -u dns ../../.venv/bin/python manage.py collectstatic --noinput
# rebuild the frontend and rsync it (step 7), then:
sudo supervisorctl restart dns:*
```

Restarting `dns-api` makes a new sign-in key: the GUI downloads it again by itself, so users are not disconnected, but a sign-in in progress is retried.

Recurring jobs (cron, as user `dns`): `manage.py import_blocklist` weekly to refresh the public lists.

The `.gitignore` excludes `.env`, the GeoIP databases, `staticfiles/` and the build folders.

## 12. Point the clients to the server

Nothing uses the server until clients ask it. Options: set the DNS server in your DHCP (option 6) or router; or set it by hand (`/etc/resolv.conf`, `resolvectl dns <iface> 192.0.2.10`, system network settings). Keep a second resolver on the clients only if you accept that internal names may fail over to it (it will answer NXDOMAIN for them).

## 13. Optional: geolocation databases

For cities and a map that work offline, download the `.mmdb` files into `/opt/dns/app/backend/geoip-data` as shown in the README, owned by `dns`, and set `GEOIP_CITY_DB`, `GEOIP_ASN_DB` in `.env` (absolute paths). They are re-read by themselves when replaced: schedule the download monthly in cron. Without them the API uses DNS lookups (Team Cymru) for country and network.

## 14. Logs, backup, maintenance

- **Logs:** supervisor writes `/var/log/supervisor/dns-*.log` and rotates them (`stdout_logfile_maxbytes`, default 50 MB, 10 backups). nginx logs are in `/var/log/nginx/` (rotated by logrotate). The DNS query history is in the database and is purged by `rundns` after `QUERY_LOG_DAYS` (default 7), together with the statistics counters.
- **Backup:** the database is the only data to protect, plus `.env`. PostgreSQL: `pg_dump -U dns dns | gzip > dns-$(date +%F).sql.gz`. MariaDB: `mariadb-dump --single-transaction dns | gzip > ...`. Run it from cron, copy it off the server, and test a restore (`psql dns < dump.sql` / `mariadb dns < dump.sql`) on a spare machine. Keep `.env` copies in a secret store: without `SECRET_KEY` nobody can use tickets signed before, but data is intact.
- **Partitioned log (MySQL/MariaDB, optional):** `manage.py partition_querylog` once splits the query log into daily partitions; `rundns` then drops old days instantly instead of running a huge `DELETE`. It rebuilds the table and writes wait meanwhile: back up first, run it when the traffic is low (see "Partitioned log" in the README).
- **Statistics counters:** the Statistics and Geolocation pages read hourly counters, not the log. `manage.py rebuild_stats` recomputes them from the log if they ever look wrong.
- **Blocklists:** cron as user `dns`, for example weekly: `0 4 * * 0  cd /opt/dns/app/backend && ../../.venv/bin/python manage.py import_blocklist`.
- **Lost second factor:** `manage.py mfa_reset <user>`.

## 15. Hardening checklist

- `.env` mode `600`, owner `dns`; the `dns` user has no shell and no sudo.
- `DEBUG=false`, long random `SECRET_KEY`, `LOGIN_ENCRYPTION=required`, `MFA_REQUIRED=true`.
- Database and Redis listen on localhost or a private network only; each has its own password; the database user has rights on its own database only.
- Firewall: only the ports in step 9; port 53 limited to your networks (never an open resolver).
- gunicorn listens on `127.0.0.1` only; the only public entry is nginx.
- Keep the system, Python packages (`pip list --outdated`) and nginx updated; `pip install -r requirements.txt` after each release.
- Only staff users can use the GUI and only superusers the Django admin: give the flags to as few people as possible.

## 16. Troubleshooting

| Symptom | Cause and fix |
|---|---|
| The API will not start: weak `SECRET_KEY` | With `DEBUG=false` the key must have at least 50 characters. Generate a new one (README, "Configuration"). |
| `DisallowedHost: Invalid HTTP_HOST header: '192.168.1.23'` | The browser used an address that is not in `ALLOWED_HOSTS`. Use the configured host name, or add the address: `ALLOWED_HOSTS=dns.example.com,192.168.1.23` (and `CSRF_TRUSTED_ORIGINS=https://dns.example.com,https://192.168.1.23`, and the IP in the certificate SAN). Passkeys never work on an IP address: sign in through the host name. |
| `502 Bad Gateway` from nginx | gunicorn is down or not on `127.0.0.1:8000`: `supervisorctl status`, `tail /var/log/supervisor/dns-api.err.log`. |
| `403` "CSRF verification failed" | `CSRF_TRUSTED_ORIGINS` is missing the exact `https://host` used in the browser, or `BEHIND_PROXY` is not `true`. |
| Sign-in answers `403` | `LOGIN_ENCRYPTION=required` refuses plain requests: use the GUI (it encrypts), not `curl` on `/api/token/`. |
| "Invalid passkey or domain not allowed" | `WEBAUTHN_RP_ID` must be the host name without port, `WEBAUTHN_ORIGINS` the full `https://…` address; the certificate must be trusted. |
| The Django admin sends you back to the GUI | Expected: it opens only from **Django admin ↗** for superusers, and the GUI and `/admin` must share the same address. |
| `OSError: Address already in use` on port 53 | Another resolver (often `systemd-resolved` on `127.0.0.53`): bind `--address` to the server IP or disable its stub listener. |
| `PermissionError` on port 53 | `setcap cap_net_bind_service` missing, or lost after a Python upgrade (step 8). |
| `Database returned an invalid datetime value` in the admin | The database lacks time zone tables: see step 4 (`mariadb-tzinfo-to-sql`), or set `TIME_ZONE=UTC`. |
| A `.env` change has no effect | Restart **both** programs: `sudo supervisorctl restart dns:*` (`dns:dns-api` and `dns:dns-daemon`). Only `backend/.env` is read, not `.env.prod`. |
| `mysqlclient` fails to build | Install `libmariadb-dev` (or `default-libmysqlclient-dev`), `pkg-config` and `build-essential`. |
| `ModuleNotFoundError: psycopg` / `MySQLdb` | The driver of step 4 is not installed in `/opt/dns/.venv`. |
| HTTP/3 does not work | UDP 443 is blocked, or nginx lacks `http_v3`; browsers fall back to HTTP/2 by themselves, so the site still works. |
| Redis errors in the log | Wrong `REDIS_URL` or password. The DNS daemon keeps working (it asks the upstream directly). |
| Sign-in fails right after an API restart | The key changed; the GUI fetches it again and retries once. A second failure: reload the page. |
