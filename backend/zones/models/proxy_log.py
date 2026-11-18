from django.db import models
from django.utils import timezone


class ProxyLog(models.Model):
    OUTCOMES = [
        ('allowed', 'allowed'),
        ('filtered', 'filtered'),
        ('blocked', 'blocked'),
        ('error', 'error'),
        ('timeout', 'timeout'),  # counted apart in the statistics: a wait that ran out says nothing about the site's speed or the proxy's error rate
    ]

    time = models.DateTimeField(default=timezone.now, editable=False, db_index=True)
    client = models.CharField(max_length=45)
    method = models.CharField(max_length=12)
    host = models.CharField(max_length=253)
    url = models.CharField(max_length=500, blank=True, default='')
    outcome = models.CharField(max_length=12, choices=OUTCOMES)
    status = models.PositiveSmallIntegerField(default=200)
    reason = models.CharField(max_length=255, blank=True, default='')
    ms = models.PositiveIntegerField(default=0)

    class Meta:
        indexes = [
            models.Index(fields=['host', 'time'], name='plog_host_time'),
            models.Index(fields=['outcome', 'time'], name='plog_outcome_time'),
            models.Index(fields=['client', 'time'], name='plog_client_time'),
        ]
