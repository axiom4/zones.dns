"""Any change to zones, records, static hosts or the blacklist raises DataVersion, which tells the DNS daemon to reload its in-memory copy.

Queryset.update() and bulk_create() send no signals: callers that use them call DataVersion.bump() themselves.
"""
from django.db import connection, transaction
from django.db.models.signals import post_delete, post_save

from .models import BlockedDomain, DataVersion, PersonalBlock, PublicBlocklistEntry, Record, StaticHost, Zone


def _bump():
    DataVersion.bump()


def changed(sender=None, **kwargs):
    # one bump per transaction, after it commits (so the daemon never reloads before the data is visible)
    if not any(c[1] is _bump for c in connection.run_on_commit):
        transaction.on_commit(_bump)


def connect():
    for model in (Zone, Record, StaticHost, BlockedDomain, PersonalBlock, PublicBlocklistEntry):
        post_save.connect(changed, sender=model, dispatch_uid=f'dv-save-{model.__name__}')
        post_delete.connect(changed, sender=model, dispatch_uid=f'dv-delete-{model.__name__}')
