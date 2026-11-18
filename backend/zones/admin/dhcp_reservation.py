from django.contrib import admin

from ..models import Dhcp6Reservation, DhcpReservation


@admin.register(DhcpReservation)
class DhcpReservationAdmin(admin.ModelAdmin):
    """Fixed DHCPv4 addresses by MAC (GUI "DHCP" > "Reservations")."""
    list_display = ['mac', 'ip', 'hostname', 'enabled', 'note']
    list_filter = ['enabled']
    list_editable = ['enabled']
    search_fields = ['mac', 'ip', 'hostname', 'note']
    readonly_fields = ['created']


@admin.register(Dhcp6Reservation)
class Dhcp6ReservationAdmin(admin.ModelAdmin):
    """Fixed DHCPv6 addresses (IA_NA) by DUID (GUI "DHCP" > "Reservations 6")."""
    list_display = ['duid', 'ip', 'enabled', 'note']
    list_filter = ['enabled']
    list_editable = ['enabled']
    search_fields = ['duid', 'ip', 'note']
    readonly_fields = ['created']
