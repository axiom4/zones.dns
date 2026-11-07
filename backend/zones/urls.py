from django.urls import path
from rest_framework.routers import DefaultRouter

from .views import AuditView, GeoDestinationsView, GeoIpsView, BlockedDomainViewSet, QueryLogViewSet, RecordViewSet, StatsView, ZoneViewSet

router = DefaultRouter()
router.register('zones', ZoneViewSet)
router.register('records', RecordViewSet, basename='record')
router.register('blocked', BlockedDomainViewSet)
router.register('logs', QueryLogViewSet, basename='log')
urlpatterns = [path('stats/', StatsView.as_view()), path('audit/', AuditView.as_view()), path('geo/ips/', GeoIpsView.as_view()), path('geo/destinations/', GeoDestinationsView.as_view()), *router.urls]
