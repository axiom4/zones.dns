from django.contrib import admin

from ..models import Passkey, TotpDevice


@admin.register(TotpDevice)
class TotpDeviceAdmin(admin.ModelAdmin):
    """Delete a row to reset a user's authenticator app (the secret is never shown)."""
    list_display = ['user', 'confirmed', 'created']
    fields = ['user', 'confirmed', 'created']
    readonly_fields = fields

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False


@admin.register(Passkey)
class PasskeyAdmin(admin.ModelAdmin):
    """Delete a row to remove a lost passkey."""
    list_display = ['user', 'name', 'created']
    fields = ['user', 'name', 'created']
    readonly_fields = fields

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False
