import os

from django.db import migrations

NAMES = (
    'DHCP DHCP_SERVER DHCP_NETMASK DHCP_RANGE DHCP_ROUTER DHCP_DNS DHCP_DOMAIN DHCP_LEASE DHCP_RESERVATIONS DHCP_INTERFACE DHCP_NTP DHCP_SEARCH DHCP_ROUTES '
    'DHCP_MTU DHCP_BOOT_SERVER DHCP_BOOT_FILE DHCP_PROBE DHCP_NAMES DHCP_UNICAST DHCP_DNR DHCP_FAILOVER_SECS DHCP_SUBNETS DHCP6 DHCP6_PREFIX DHCP6_POOL '
    'DHCP6_PD_POOL DHCP6_PD_LEN DHCP6_PD_ROUTES DHCP6_LEASE DHCP6_PREFERENCE DHCP6_RAPID DHCP6_DNS DHCP_RA DHCP_RA_INTERVAL DHCP_RA_ROUTER_LIFETIME DHCP_RA_SLAAC'
).split()
BOOLS = {'DHCP', 'DHCP_PROBE', 'DHCP_NAMES', 'DHCP_UNICAST', 'DHCP_DNR', 'DHCP6', 'DHCP6_PD_ROUTES', 'DHCP6_RAPID', 'DHCP_RA', 'DHCP_RA_SLAAC'}


def from_env(apps, schema_editor):
    """The DHCP settings used to be in .env; they live in the database now. Whatever .env still sets (and the GUI has not saved) is kept once."""
    Setting = apps.get_model('zones', 'Setting')
    Setting.objects.filter(key__startswith='dhcp-env:').delete()
    for name in NAMES:
        raw = os.environ.get(name)
        if raw is None or Setting.objects.filter(key=f'dhcp:{name}').exists():
            continue
        if name in BOOLS:
            raw = 'true' if raw.strip().lower() in ('1', 'true', 'yes', 'on') else 'false'
        Setting.objects.create(key=f'dhcp:{name}', value=raw.strip())


class Migration(migrations.Migration):
    dependencies = [('zones', '0033_macvendor')]
    operations = [migrations.RunPython(from_env, migrations.RunPython.noop)]
