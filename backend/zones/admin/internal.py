from django.contrib import admin

from ..models import DataVersion, LogTotal, MacVendor


class ReadOnlyAdmin(admin.ModelAdmin):
    """Tables kept by the application itself: visible for checking, never edited by hand (a wrong value would desynchronise the daemons or the counters)."""
    actions = None
    show_full_result_count = False

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False


@admin.register(DataVersion)
class DataVersionAdmin(ReadOnlyAdmin):
    """The change counter the DNS daemon watches to reload zones, records and the blacklist."""
    list_display = ['pk', 'n']


@admin.register(LogTotal)
class LogTotalAdmin(ReadOnlyAdmin):
    """All-time log totals per outcome / type / client (rollup.py)."""
    list_display = ['dim', 'key', 'n']
    list_filter = ['dim']
    search_fields = ['key']
    list_per_page = 100


@admin.register(MacVendor)
class MacVendorAdmin(ReadOnlyAdmin):
    """The IEEE vendor table, filled by `manage.py update_oui`."""
    list_display = ['prefix', 'name']
    search_fields = ['prefix', 'name']
    list_per_page = 100
