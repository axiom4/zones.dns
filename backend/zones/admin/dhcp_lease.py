from django.contrib import admin

from ..models import Dhcp6Lease, DhcpLease


@admin.register(DhcpLease)
class DhcpLeaseAdmin(admin.ModelAdmin):
    """The addresses handed out by rundhcp: look, or delete one to free the address."""
    list_display = ['ip', 'mac', 'hostname', 'expires']
    search_fields = ['ip', 'mac', 'hostname']

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False


@admin.register(Dhcp6Lease)
class Dhcp6LeaseAdmin(DhcpLeaseAdmin):
    list_display = ['value', 'kind', 'duid', 'iaid', 'expires']
    search_fields = ['value', 'duid']
