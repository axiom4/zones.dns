from django.contrib import admin
from django.db.models import Count

from ..models import Zone
from ..dnsd.reverse import zone_to_cidr


@admin.register(Zone)
class ZoneAdmin(admin.ModelAdmin):
    list_display = ['name', 'enabled', 'kind', 'record_count']
    list_editable = ['enabled']
    list_filter = ['enabled']
    search_fields = ['name']
    ordering = ['name']

    def get_queryset(self, request):
        return super().get_queryset(request).annotate(_records=Count('records'))

    @admin.display(description='Type')
    def kind(self, z):
        cidr = zone_to_cidr(z.name)
        return f'reverse ({cidr})' if cidr else 'forward'

    @admin.display(description='Records', ordering='_records')
    def record_count(self, z):
        return z._records
