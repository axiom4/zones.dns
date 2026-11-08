from django.apps import AppConfig


class ZonesConfig(AppConfig):
    name = 'zones'

    def ready(self):
        from . import signals
        signals.connect()
