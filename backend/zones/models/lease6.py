from django.db import models


class Dhcp6Lease(models.Model):
    """An address (IA_NA) or a delegated prefix (IA_PD) the DHCPv6 server gave to a client, named by its DUID and the IAID of the association."""
    duid = models.CharField(max_length=260)  # hex; "declined" for an address a client refused
    iaid = models.PositiveBigIntegerField()
    kind = models.CharField(max_length=2)  # 'na' or 'pd'
    value = models.CharField(max_length=43, unique=True)  # the address, or the prefix as 2001:db8::/56
    expires = models.DateTimeField(db_index=True)
    updated = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['kind', 'value']
        constraints = [models.UniqueConstraint(fields=['duid', 'iaid', 'kind'], name='unique_dhcp6_ia')]
        verbose_name, verbose_name_plural = 'DHCPv6 lease', 'DHCPv6 leases'

    def __str__(self):
        return f'{self.value} {self.duid[:16]}'
