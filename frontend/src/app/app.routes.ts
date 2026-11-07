import { Routes } from '@angular/router';
import { authGuard } from './auth';
import { Shell } from './shell';

export const routes: Routes = [
  { path: 'login', loadComponent: () => import('./login').then(m => m.Login) },
  {
    path: '',
    component: Shell,
    canActivate: [authGuard],
    children: [
      { path: '', pathMatch: 'full', redirectTo: 'zones' },
      { path: 'zones', loadComponent: () => import('./zones-index').then(m => m.ZonesIndex) },
      { path: 'zones/:id', loadComponent: () => import('./zone-page').then(m => m.ZonePage) },
      { path: 'blacklist', pathMatch: 'full', redirectTo: 'blacklist/manual' },
      { path: 'blacklist/manual', loadComponent: () => import('./blocked-page').then(m => m.BlockedPage) },
      { path: 'blacklist/lists', loadComponent: () => import('./blocked-lists-page').then(m => m.BlockedListsPage) },
      { path: 'blocked', redirectTo: 'blacklist/manual' },
      { path: 'geo', loadComponent: () => import('./geo-page').then(m => m.GeoPage) }, // lazy: pulls in the map libraries
      { path: 'audit', loadComponent: () => import('./audit-page').then(m => m.AuditPage) },
      { path: 'logs', loadComponent: () => import('./logs-page').then(m => m.LogsPage) },
      { path: 'security', loadComponent: () => import('./security-page').then(m => m.SecurityPage) },
      { path: 'stats', loadComponent: () => import('./stats-page').then(m => m.StatsPage) },
    ],
  },
  { path: '**', redirectTo: '' },
];
