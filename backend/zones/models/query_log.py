from django.db import models
from django.utils import timezone


class QueryLog(models.Model):
    OUTCOMES = [('local', 'local'), ('forwarded', 'forwarded'), ('blocked', 'blocked'), ('error', 'error')]

    time = models.DateTimeField(default=timezone.now, editable=False, db_index=True)  # set when the query arrives (the row may be saved a moment later)
    name = models.CharField(max_length=253, db_index=True)
    domain = models.CharField(max_length=253, db_index=True, default='')  # registrable domain of name
    type = models.CharField(max_length=10)
    outcome = models.CharField(max_length=10, choices=OUTCOMES)
    client = models.CharField(max_length=45)
    ms = models.PositiveIntegerField()
    rcode = models.CharField(max_length=10, blank=True, default='')  # NOERROR, NXDOMAIN, SERVFAIL...
    via = models.CharField(max_length=300, blank=True, default='')  # who answered: zone, blacklist entry or upstream
    answers = models.JSONField(default=list, blank=True)  # [{name, type, value, ttl}]

    class Meta:
        indexes = [
            models.Index(fields=['domain', 'time'], name='qlog_domain_time'),
            models.Index(fields=['outcome', 'time'], name='qlog_outcome_time'),
        ]
