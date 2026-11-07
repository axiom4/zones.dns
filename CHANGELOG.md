# Changelog

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
