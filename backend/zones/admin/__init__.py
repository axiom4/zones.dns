from .dhcp_lease import DhcpLeaseAdmin
from .blocked_domain import PersonalBlockAdmin, PublicBlocklistAdmin
from .ip_geo import IpGeoAdmin
from .mfa import PasskeyAdmin, TotpDeviceAdmin
from .query_log import QueryLogAdmin
from .record import RecordAdmin
from .setting import SettingAdmin
from .stat import DomainStatAdmin, GeoStatAdmin, StatCountAdmin
from .static_host import StaticHostAdmin
from .zone import ZoneAdmin

__all__ = ['PasskeyAdmin', 'TotpDeviceAdmin', 'IpGeoAdmin', 'PersonalBlockAdmin', 'PublicBlocklistAdmin', 'QueryLogAdmin', 'RecordAdmin', 'SettingAdmin', 'StatCountAdmin', 'GeoStatAdmin', 'DomainStatAdmin', 'StaticHostAdmin', 'ZoneAdmin']


from django.contrib import admin as _admin  # noqa: E402

# The Django admin is for superusers only: staff users (who may use the GUI) get no admin permission at all.
_admin.site.has_permission = lambda request: request.user.is_active and request.user.is_superuser
_admin.site.site_header = _admin.site.site_title = 'Zones.dns'
_admin.site.index_title = 'Administration'
