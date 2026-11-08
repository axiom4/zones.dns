from django.contrib import admin

from ..models import StaticHost


@admin.register(StaticHost)
class StaticHostAdmin(admin.ModelAdmin):
    """Names answered with a fixed address, like /etc/hosts (GUI "Hosts")."""
    list_display = ['name', 'address', 'ttl', 'enabled', 'note']
    list_filter = ['enabled']
    list_editable = ['enabled']
    search_fields = ['name', 'address', 'note']
    readonly_fields = ['created']

    def save_model(self, request, obj, form, change):
        obj.name = obj.name.strip().strip('.').lower()  # same normalisation as the API
        super().save_model(request, obj, form, change)
