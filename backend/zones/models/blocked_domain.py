from django.db import models


class BlockedDomain(models.Model):
    name = models.CharField(max_length=253, unique=True)  # blocks the name and all its subdomains
    created = models.DateTimeField(auto_now_add=True)
    enabled = models.BooleanField(default=True)  # disabled entries are kept but do not block
    allow = models.BooleanField(default=False)  # an exception: the name and its subdomains are never blocked, unless a longer entry says so
    regex = models.BooleanField(default=False)  # name is a pattern (re.search on the queried name) instead of a domain
    expires = models.DateTimeField(null=True, blank=True)  # temporary entry: ignored after this time
    list_name = models.CharField(max_length=40, blank=True, default='', db_index=True)  # which public list an imported entry came from
    source = models.CharField(max_length=10, default='manual', db_index=True)  # manual = added by hand; list = imported by import_blocklist


class PersonalBlock(BlockedDomain):
    """Admin section: domains blocked by hand (same table, source=manual)."""
    class Meta:
        proxy = True
        verbose_name, verbose_name_plural = 'personal block', 'personal blocks'


class PublicBlocklistEntry(BlockedDomain):
    """Admin section: domains imported by import_blocklist (same table, source=list)."""
    class Meta:
        proxy = True
        verbose_name, verbose_name_plural = 'public list entry', 'public lists'
