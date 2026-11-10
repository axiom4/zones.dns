from django.db import models


class Setting(models.Model):
    """Switches that the GUI changes and the DNS daemon follows (a change raises DataVersion, see signals.py)."""
    key = models.CharField(max_length=50, primary_key=True)
    value = models.CharField(max_length=255, blank=True)

    @classmethod
    def flag(cls, key, default=True):
        v = cls.objects.filter(key=key).values_list('value', flat=True).first()
        return default if v is None else v == 'true'

    @classmethod
    def set_flag(cls, key, on):
        cls.objects.update_or_create(key=key, defaults={'value': 'true' if on else 'false'})

PERSONAL_BLOCKS = 'personal_blocks'  # the whole feature: false = blocks added by hand are ignored
PUBLIC_LISTS = 'public_lists'  # false = the imported public lists are ignored
LISTS_OFF = 'lists_off'  # comma-separated names of the public lists that are switched off
