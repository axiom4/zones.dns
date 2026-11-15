from django.contrib import admin

from ..models import DhcpReservation


@admin.register(DhcpReservation)
class DhcpReservationAdmin(admin.ModelAdmin):
    """Fixed DHCPv4 addresses by MAC (GUI "DHCP" > "Reservations")."""
    list_display = ['mac', 'ip', 'hostname', 'enabled', 'note']
    list_filter = ['enabled']
    list_editable = ['enabled']
    search_fields = ['mac', 'ip', 'hostname', 'note']
    readonly_fields = ['created']
