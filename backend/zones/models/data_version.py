from django.conf import settings
from django.core.cache import cache
from django.db import models
from django.db.models import F


class DataVersion(models.Model):
    """One row (pk=1) whose counter goes up whenever zones, records or the blacklist change: the DNS daemon (another process) watches it."""
    n = models.BigIntegerField(default=0)

    @classmethod
    def bump(cls):
        if not cls.objects.filter(pk=1).update(n=F('n') + 1):
            _, created = cls.objects.get_or_create(pk=1, defaults={'n': 1})
            if not created:
                cls.objects.filter(pk=1).update(n=F('n') + 1)
        if settings.REDIS_URL:
            try:
                cache.set('data:ver', cls.current(), None)
            except Exception:
                pass  # Redis down: the daemon reads the database counter instead

    @classmethod
    def version(cls):
        """What the DNS daemon compares. With Redis the counter lives there too (one cheap GET per query); the database copy is the truth."""
        if settings.REDIS_URL:
            try:
                v = cache.get('data:ver')
                if v is None:
                    v = cls.current()
                    cache.add('data:ver', v, None)
                return v
            except Exception:
                pass  # Redis down: fall back to the database
        return cls.current()

    @classmethod
    def current(cls):
        return cls.objects.filter(pk=1).values_list('n', flat=True).first() or 0
