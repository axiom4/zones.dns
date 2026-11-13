from django.urls import path
from rest_framework.routers import DefaultRouter

from .views.dhcp import DhcpLeasesView, DhcpLeaseView, DhcpSettingsView
from .views import AuditView, GeoDestinationsView, GeoIpsView, WhoisView, BlockedDomainViewSet, QueryLogViewSet, RecordViewSet, StaticHostViewSet, StatsView, ZoneViewSet

router = DefaultRouter()
router.register('zones', ZoneViewSet)
router.register('records', RecordViewSet, basename='record')
router.register('hosts', StaticHostViewSet)
router.register('blocked', BlockedDomainViewSet)
router.register('logs', QueryLogViewSet, basename='log')
urlpatterns = [path('dhcp/leases/', DhcpLeasesView.as_view()), path('dhcp/leases/<int:family>/<int:pk>/', DhcpLeaseView.as_view()), path('dhcp/settings/', DhcpSettingsView.as_view()), path('stats/', StatsView.as_view()), path('audit/', AuditView.as_view()), path('geo/ips/', GeoIpsView.as_view()), path('geo/whois/', WhoisView.as_view()), path('geo/destinations/', GeoDestinationsView.as_view()), *router.urls]
