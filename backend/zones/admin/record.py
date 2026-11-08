from django.contrib import admin

from django.db import transaction

from ..models import DataVersion, Record


@admin.register(Record)
class RecordAdmin(admin.ModelAdmin):
    list_display = ['fqdn', 'type', 'value', 'ttl', 'enabled', 'note', 'zone']
    list_editable = ['enabled']
    list_filter = ['zone', 'type', 'enabled']
    search_fields = ['name', 'value', 'note']
    list_select_related = ['zone']
    autocomplete_fields = ['zone']
    list_per_page = 100
    ordering = ['zone__name', 'name', 'type']
    actions = ['enable', 'disable']

    @admin.display(description='Name', ordering='name')
    def fqdn(self, r):
        return r.fqdn

    @admin.action(description='Enable the selected records')
    def enable(self, request, qs):
        self.message_user(request, f'{qs.update(enabled=True)} records enabled.')
        transaction.on_commit(DataVersion.bump)

    @admin.action(description='Disable the selected records')
    def disable(self, request, qs):
        self.message_user(request, f'{qs.update(enabled=False)} records disabled.')
        transaction.on_commit(DataVersion.bump)
