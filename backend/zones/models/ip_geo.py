from django.db import models


class IpGeo(models.Model):
    """Cached location of a public IP (country, network). Filled on demand, never while answering DNS queries."""
    ip = models.CharField(max_length=45, unique=True)
    country = models.CharField(max_length=2, blank=True)  # ISO 3166 alpha-2; empty = unknown
    asn = models.CharField(max_length=16, blank=True)
    as_name = models.CharField(max_length=200, blank=True)
    prefix = models.CharField(max_length=64, blank=True)
    updated = models.DateTimeField(auto_now=True)
