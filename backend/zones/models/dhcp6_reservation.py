from django.db import models
from django.db.models.signals import post_delete, post_save
from django.dispatch import receiver

from .data_version import DataVersion


class Dhcp6Reservation(models.Model):
    """A fixed DHCPv6 address (IA_NA) for one client, named by its DUID: the client always gets this address and nobody else is given it (rundhcp reads the table live)."""
    duid = models.CharField(max_length=260, unique=True)  # hex, lower case, no separators
    ip = models.GenericIPAddressField(protocol='IPv6', unique=True)
    note = models.CharField(max_length=255, blank=True)
    enabled = models.BooleanField(default=True)  # disabled reservations are kept but not used
    created = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['ip']
        verbose_name, verbose_name_plural = 'DHCPv6 reservation', 'DHCPv6 reservations'

    def __str__(self):
        return f'{self.duid[:16]} = {self.ip}'


@receiver([post_save, post_delete], sender=Dhcp6Reservation)
def _changed(sender, **kw):
    DataVersion.bump()
