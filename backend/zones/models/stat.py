from django.db import models


class StatCount(models.Model):
    """Hourly counters kept next to the query log, so the statistics read a few rows instead of scanning the log (see rollup.py).

    dim says what key is: outcome, type, name, client, or blocked (names that were blocked). Times are UTC, whole hours.
    """
    dim = models.CharField(max_length=10)
    hour = models.DateTimeField()
    key = models.CharField(max_length=253, blank=True)
    n = models.PositiveBigIntegerField(default=0)  # queries
    ms = models.PositiveBigIntegerField(default=0)  # sum of the answer times

    class Meta:
        constraints = [models.UniqueConstraint(fields=['dim', 'hour', 'key'], name='unique_stat_count')]


class GeoStat(models.Model):
    """Hourly count of the A/AAAA addresses answered for a registrable domain: what the geolocation page aggregates."""
    hour = models.DateTimeField()
    domain = models.CharField(max_length=253, blank=True)
    ip = models.CharField(max_length=45)
    n = models.PositiveBigIntegerField(default=0)

    class Meta:
        constraints = [models.UniqueConstraint(fields=['hour', 'domain', 'ip'], name='unique_geo_stat')]


class DomainStat(models.Model):
    """Hourly per-domain summary counters for fast long-period grouped query-log queries."""
    hour = models.DateTimeField()
    domain = models.CharField(max_length=253, blank=True)
    n = models.PositiveBigIntegerField(default=0)
    local = models.PositiveBigIntegerField(default=0)
    forwarded = models.PositiveBigIntegerField(default=0)
    blocked = models.PositiveBigIntegerField(default=0)
    error = models.PositiveBigIntegerField(default=0)
    ms = models.PositiveBigIntegerField(default=0)

    class Meta:
        constraints = [models.UniqueConstraint(fields=['hour', 'domain'], name='unique_domain_stat')]
        indexes = [models.Index(fields=['domain', 'hour'], name='idx_domain_stat_dom_hr')]
