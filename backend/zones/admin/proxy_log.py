from django.contrib import admin

from ..models import ProxyLog


@admin.register(ProxyLog)
class ProxyLogAdmin(admin.ModelAdmin):
    """Read-only: the proxy writes the log. Purge from the GUI / API (chunked), not with the bulk delete."""
    list_display = ['time', 'client', 'method', 'host', 'outcome', 'status', 'ms']
    list_filter = ['outcome']
    search_fields = ['host', 'client', 'url', 'reason']
    list_per_page = 100
    show_full_result_count = False
    fields = ['time', 'client', 'method', 'host', 'url', 'outcome', 'status', 'reason', 'ms']
    readonly_fields = fields
    actions = None

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False
