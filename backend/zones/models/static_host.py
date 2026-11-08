from django.db import models


class StaticHost(models.Model):
    """Like a line of /etc/hosts: queries for this exact name are answered with this address, whatever the real DNS says.

    A name may have several addresses (several rows). The name is answered for A (IPv4 rows) and AAAA (IPv6 rows); any other type gets an
    empty answer, so nothing from the real DNS leaks through. Wins over zones, the blacklist and the upstream.
    """
    name = models.CharField(max_length=253, db_index=True)  # lowercase, no trailing dot, exact match (no wildcards)
    address = models.GenericIPAddressField()
    ttl = models.PositiveIntegerField(default=300)
    enabled = models.BooleanField(default=True)  # disabled hosts are kept but never served
    note = models.CharField(max_length=255, blank=True)
    created = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['name', 'address']
        constraints = [models.UniqueConstraint(fields=['name', 'address'], name='unique_static_host')]
        verbose_name, verbose_name_plural = 'static host', 'static hosts'

    def __str__(self):
        return f'{self.address} {self.name}'
