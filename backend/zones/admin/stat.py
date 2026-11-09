from django.contrib import admin

from ..models import GeoStat, StatCount


class ReadOnlyAdmin(admin.ModelAdmin):
    """Counters kept by the daemon (rollup.py): look only; rebuild_stats recomputes them from the log."""
    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False


@admin.register(StatCount)
class StatCountAdmin(ReadOnlyAdmin):
    list_display = ['hour', 'dim', 'key', 'n', 'ms']
    list_filter = ['dim']
    search_fields = ['key']
    date_hierarchy = 'hour'


@admin.register(GeoStat)
class GeoStatAdmin(ReadOnlyAdmin):
    list_display = ['hour', 'domain', 'ip', 'n']
    search_fields = ['domain', 'ip']
    date_hierarchy = 'hour'
