import json

from django.contrib import admin

from ..models import QueryLog


@admin.register(QueryLog)
class QueryLogAdmin(admin.ModelAdmin):
    """Read-only: the daemon writes the log. Deleting (e.g. old rows) is allowed."""
    list_display = ['time', 'name', 'type', 'outcome', 'rcode', 'via', 'client', 'ms']
    list_filter = ['outcome', 'type', 'rcode']
    search_fields = ['name', 'domain', 'client', 'via']
    date_hierarchy = 'time'
    list_per_page = 100
    show_full_result_count = False
    fields = ['time', 'name', 'domain', 'type', 'outcome', 'rcode', 'via', 'client', 'ms', 'answers_pretty']
    readonly_fields = fields

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    @admin.display(description='Answer')
    def answers_pretty(self, log):
        return json.dumps(log.answers, indent=2, ensure_ascii=False) if log.answers else '—'
