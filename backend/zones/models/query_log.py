from django.db import models


class QueryLog(models.Model):
    OUTCOMES = [('local', 'local'), ('forwarded', 'forwarded'), ('blocked', 'blocked'), ('error', 'error')]

    time = models.DateTimeField(auto_now_add=True, db_index=True)
    name = models.CharField(max_length=253)
    domain = models.CharField(max_length=253, db_index=True, default='')  # registrable domain of name
    type = models.CharField(max_length=10)
    outcome = models.CharField(max_length=10, choices=OUTCOMES)
    client = models.CharField(max_length=45)
    ms = models.PositiveIntegerField()
    rcode = models.CharField(max_length=10, blank=True, default='')  # NOERROR, NXDOMAIN, SERVFAIL...
    via = models.CharField(max_length=300, blank=True, default='')  # who answered: zone, blacklist entry or upstream
    answers = models.JSONField(default=list, blank=True)  # [{name, type, value, ttl}]
