from django.contrib import admin

from ..models import Setting
from ..proxy.ca import CA_PRIV_KEY


@admin.register(Setting)
class SettingAdmin(admin.ModelAdmin):
    """The master switches the GUI changes (personal_blocks, public_lists): 'true' or 'false'."""
    list_display = ['key', 'value']
    search_fields = ['key']

    def get_queryset(self, request):
        # the Proxy Root CA private key is never shown: whoever reads it can intercept HTTPS on every device that trusts the CA
        return super().get_queryset(request).exclude(key=CA_PRIV_KEY)
