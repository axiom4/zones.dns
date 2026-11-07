from django.contrib import admin

from ..models import IpGeo


@admin.register(IpGeo)
class IpGeoAdmin(admin.ModelAdmin):
    """Cache of IP locations. Deleting rows just makes them be looked up again."""
    list_display = ['ip', 'country', 'asn', 'as_name', 'prefix', 'updated']
    list_filter = ['country']
    search_fields = ['ip', 'as_name', 'asn', 'prefix']
    readonly_fields = ['updated']
    date_hierarchy = 'updated'
    list_per_page = 100
