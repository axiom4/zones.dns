from django.contrib import admin

from ..models import Setting


@admin.register(Setting)
class SettingAdmin(admin.ModelAdmin):
    """The master switches the GUI changes (personal_blocks, public_lists): 'true' or 'false'."""
    list_display = ['key', 'value']
    search_fields = ['key']
