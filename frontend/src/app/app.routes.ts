import { Routes } from '@angular/router';
import { authGuard } from './services/auth';
import { Shell } from './shell/shell';

export const routes: Routes = [
  { path: 'login', title: 'Sign in', loadComponent: () => import('./login/login').then(m => m.Login) },
  {
    path: '',
    component: Shell,
    canActivate: [authGuard],
    children: [
      { path: '', pathMatch: 'full', redirectTo: 'zones' },
      { path: 'zones', title: 'Zones', loadComponent: () => import('./zones-index/zones-index').then(m => m.ZonesIndex) },
      { path: 'zones/hosts', title: 'Static hosts', loadComponent: () => import('./hosts-page/hosts-page').then(m => m.HostsPage) },
      { path: 'zones/:id', title: 'Zone', loadComponent: () => import('./zone-page/zone-page').then(m => m.ZonePage) },
      { path: 'hosts', redirectTo: 'zones/hosts' },
      { path: 'dhcp', pathMatch: 'full', redirectTo: 'dhcp/leases' },
      { path: 'dhcp/proxy', redirectTo: 'proxy/settings' }, // the proxy has a section of its own
      { path: 'dhcp/proxy-logs', redirectTo: 'logs/proxy' },
      { path: 'dhcp/:tab', title: 'DHCP', loadComponent: () => import('./dhcp-page/dhcp-page').then(m => m.DhcpPage) },
      { path: 'proxy', pathMatch: 'full', redirectTo: 'proxy/settings' },
      { path: 'proxy/logs', redirectTo: 'logs/proxy' },
      { path: 'proxy/:tab', title: 'Proxy', loadComponent: () => import('./proxy-page/proxy-page').then(m => m.ProxyPage) },
      { path: 'blacklist', pathMatch: 'full', redirectTo: 'blacklist/manual' },
      { path: 'blacklist/manual', title: 'Blocklist', loadComponent: () => import('./blocked-page/blocked-page').then(m => m.BlockedPage) },
      { path: 'blacklist/lists', title: 'Blocklists', loadComponent: () => import('./blocked-lists-page/blocked-lists-page').then(m => m.BlockedListsPage) },
      { path: 'blocked', redirectTo: 'blacklist/manual' },
      { path: 'geo', title: 'Geolocation', loadComponent: () => import('./geo-page/geo-page').then(m => m.GeoPage) }, // lazy: pulls in the map libraries
      { path: 'audit', title: 'Domain audit', loadComponent: () => import('./audit-page/audit-page').then(m => m.AuditPage) },
      { path: 'logs', pathMatch: 'full', redirectTo: 'logs/dns' },
      { path: 'logs/dns', title: 'DNS log', loadComponent: () => import('./logs-page/logs-page').then(m => m.LogsPage) },
      { path: 'logs/proxy', title: 'Proxy log', data: { tab: 'logs' }, loadComponent: () => import('./proxy-page/proxy-page').then(m => m.ProxyPage) },
      { path: 'security', title: 'Security', loadComponent: () => import('./security-page/security-page').then(m => m.SecurityPage) },
      { path: 'stats', title: 'Statistics', loadComponent: () => import('./stats-page/stats-page').then(m => m.StatsPage) },
    ],
  },
  { path: '**', redirectTo: '' },
];
