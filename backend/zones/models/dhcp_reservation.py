from django.db import models
from django.db.models.signals import post_delete, post_save
from django.dispatch import receiver

from .data_version import DataVersion


class DhcpReservation(models.Model):
    """A fixed DHCPv4 address for one MAC: the client with this MAC always gets this address (rundhcp reads the table live; DHCP_RESERVATIONS in .env still works)."""
    mac = models.CharField(max_length=17, unique=True)  # aa:bb:cc:dd:ee:ff, lower case
    ip = models.GenericIPAddressField(protocol='IPv4', unique=True)
    hostname = models.CharField(max_length=63, blank=True)  # answered by the DNS server as <hostname>.<DHCP_DOMAIN> (DHCP_NAMES), whatever the client calls itself
    note = models.CharField(max_length=255, blank=True)
    enabled = models.BooleanField(default=True)  # disabled reservations are kept but not used
    created = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['ip']
        verbose_name, verbose_name_plural = 'DHCP reservation', 'DHCP reservations'

    def __str__(self):
        return f'{self.mac} = {self.ip}'


@receiver([post_save, post_delete], sender=DhcpReservation)
def _changed(sender, **kw):
    DataVersion.bump()  # rundhcp watches the counter
