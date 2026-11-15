from django.db import models


class MacVendor(models.Model):
    """The maker of a block of MAC addresses (IEEE registry): prefix is the block in upper case hex, 6, 7 or 9 digits (24, 28 or 36 bits). Filled by `manage.py update_oui`."""
    prefix = models.CharField(max_length=9, primary_key=True)
    name = models.CharField(max_length=255)

    class Meta:
        verbose_name, verbose_name_plural = 'MAC vendor', 'MAC vendors'

    def __str__(self):
        return f'{self.prefix} {self.name}'
