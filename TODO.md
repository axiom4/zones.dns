# TODO

Open work, from the CHANGELOG "not done" notes and what needs a physical network/database to verify. Most important first.

## To verify on target hardware before relying on it

- **DHCP with a real client and router.** Synthetic packets, UDP loopback sockets, ARP probe frames and L2 unicast framing are covered by automated tests. Check an offer, an ack, a renewal and a release with one physical client (`dhclient -v`, a phone) before moving the network.
- **Linux raw/multicast sockets on a real interface:** the DHCPv6 multicast group (`ff02::1:2`), the raw ICMPv6 socket of the Router Advertisements (`DHCP_RA`), and the `AF_PACKET` sockets (`DHCP_UNICAST`, ARP probe) require a Linux network interface with `CAP_NET_RAW`.
- **DNR / DDR against external routers.** The RFC 9463 byte layout and `manage.py dnr_options` (`--format dnsmasq` / `--format kea`) and `manage.py check_ddr` (with real X.509 CA + SAN verification) are covered by automated tests; check the generated lines with your router's version of dnsmasq or Kea.
- **Query log and map on MySQL.** The speed measurements (4 million rows) are SQLite only. The map period fix (`GeoStat` totals per address, cache `STALE`) and `unique_fields` of `IpGeo.bulk_create` should be verified on production MySQL/MariaDB data.

## Security (operational)

- **`DEBUG=false` in production.** Verified in `.env.prod`; ensure `/opt/dns/app/backend/.env` on the server also has `DEBUG=false` and a fresh `DATABASE_URL` password (`chmod 600`).
- **DoH (`/dns-query`) and DoT have no login.** Keep them to your own network (nginx `allow` / `deny`, firewall). The daemon logs DoH clients as 127.0.0.1.
