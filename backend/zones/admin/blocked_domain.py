from django.contrib import admin

from ..models import PersonalBlock, PublicBlocklistEntry


class SourceAdmin(admin.ModelAdmin):
    source = ''
    search_fields = ['name']
    readonly_fields = ['created']
    list_per_page = 100
    show_full_result_count = False  # imported lists have tens of thousands of rows

    def get_queryset(self, request):
        return super().get_queryset(request).filter(source=self.source)


@admin.register(PersonalBlock)
class PersonalBlockAdmin(SourceAdmin):
    """Domains blocked by hand (GUI "Blocchi personali")."""
    source = 'manual'
    list_display = ['name', 'created']
    fields = ['name', 'created']

    def save_model(self, request, obj, form, change):
        obj.name = obj.name.strip().strip('.').lower()  # same normalisation as the API
        obj.source = 'manual'
        super().save_model(request, obj, form, change)


@admin.register(PublicBlocklistEntry)
class PublicBlocklistAdmin(SourceAdmin):
    """Imported by import_blocklist, replaced at every run: read-only, deleting an entry only lasts until the next import."""
    source = 'list'
    list_display = ['name', 'created']
    fields = ['name', 'created']

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False
