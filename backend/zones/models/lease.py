from django.db import models


class DhcpLease(models.Model):
    """An address the DHCP server (rundhcp) gave to a client. An offer is kept for a minute, a lease for DHCP_LEASE seconds; a declined address or one that
    answered a ping is kept out of the pool for ten minutes."""
    client = models.CharField(max_length=140, unique=True)  # the client identifier (option 61, RFC 6842) in hex, or the MAC; "declined-<ip>" / "conflict-<ip>" for a blocked address
    mac = models.CharField(max_length=17, blank=True)  # aa:bb:cc:dd:ee:ff
    ip = models.GenericIPAddressField(protocol='IPv4', unique=True)
    hostname = models.CharField(max_length=63, blank=True)  # what the client called itself (letters, digits, "-"); answered by the DNS server as <hostname>.<DHCP_DOMAIN>
    expires = models.DateTimeField(db_index=True)
    updated = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['ip']
        verbose_name, verbose_name_plural = 'DHCP lease', 'DHCP leases'

    def __str__(self):
        return f'{self.ip} {self.mac or self.client}'
