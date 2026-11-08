import { Routes } from '@angular/router';
import { authGuard } from './services/auth';
import { Shell } from './shell/shell';

export const routes: Routes = [
  { path: 'login', loadComponent: () => import('./login/login').then(m => m.Login) },
  {
    path: '',
    component: Shell,
    canActivate: [authGuard],
    children: [
      { path: '', pathMatch: 'full', redirectTo: 'zones' },
      { path: 'zones', loadComponent: () => import('./zones-index/zones-index').then(m => m.ZonesIndex) },
      { path: 'zones/:id', loadComponent: () => import('./zone-page/zone-page').then(m => m.ZonePage) },
      { path: 'hosts', loadComponent: () => import('./hosts-page/hosts-page').then(m => m.HostsPage) },
      { path: 'blacklist', pathMatch: 'full', redirectTo: 'blacklist/manual' },
      { path: 'blacklist/manual', loadComponent: () => import('./blocked-page/blocked-page').then(m => m.BlockedPage) },
      { path: 'blacklist/lists', loadComponent: () => import('./blocked-lists-page/blocked-lists-page').then(m => m.BlockedListsPage) },
      { path: 'blocked', redirectTo: 'blacklist/manual' },
      { path: 'geo', loadComponent: () => import('./geo-page/geo-page').then(m => m.GeoPage) }, // lazy: pulls in the map libraries
      { path: 'audit', loadComponent: () => import('./audit-page/audit-page').then(m => m.AuditPage) },
      { path: 'logs', loadComponent: () => import('./logs-page/logs-page').then(m => m.LogsPage) },
      { path: 'security', loadComponent: () => import('./security-page/security-page').then(m => m.SecurityPage) },
      { path: 'stats', loadComponent: () => import('./stats-page/stats-page').then(m => m.StatsPage) },
    ],
  },
  { path: '**', redirectTo: '' },
];
