from django.urls import path
from rest_framework.routers import DefaultRouter

from .views.dhcp import DhcpLeasesView, DhcpLeaseView, DhcpNeighborsView, DhcpSettingsView, MacVendorView, PingView
from .views import AuditView, GeoDestinationsView, GeoIpsView, WhoisView, BlockedDomainViewSet, QueryLogViewSet, RecordViewSet, Dhcp6ReservationViewSet, DhcpReservationViewSet, StaticHostViewSet, StatsView, ZoneViewSet

router = DefaultRouter()
router.register('zones', ZoneViewSet)
router.register('records', RecordViewSet, basename='record')
router.register('hosts', StaticHostViewSet)
router.register('dhcp/reservations', DhcpReservationViewSet)
router.register('dhcp/reservations6', Dhcp6ReservationViewSet)
router.register('blocked', BlockedDomainViewSet)
router.register('logs', QueryLogViewSet, basename='log')
urlpatterns = [path('dhcp/leases/', DhcpLeasesView.as_view()), path('dhcp/leases/<int:family>/<int:pk>/', DhcpLeaseView.as_view()), path('dhcp/settings/', DhcpSettingsView.as_view()), path('dhcp/neighbors/', DhcpNeighborsView.as_view()), path('dhcp/vendor/', MacVendorView.as_view()), path('dhcp/ping/', PingView.as_view()), path('stats/', StatsView.as_view()), path('audit/', AuditView.as_view()), path('geo/ips/', GeoIpsView.as_view()), path('geo/whois/', WhoisView.as_view()), path('geo/destinations/', GeoDestinationsView.as_view()), *router.urls]
