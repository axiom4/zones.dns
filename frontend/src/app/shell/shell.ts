import { AfterViewInit, Component, ElementRef, effect, inject, signal, viewChild } from '@angular/core';
import { toSignal } from '@angular/core/rxjs-interop';
import { FormsModule } from '@angular/forms';
import { NavigationEnd, Router, RouterLink, RouterLinkActive, RouterOutlet } from '@angular/router';
import { filter, map } from 'rxjs';
import { Api } from '../api/api';
import { adminTicketCreate, meRetrieve } from '../api/functions';
import { Auth } from '../services/auth';
import { cidrToZone } from '../lib/reverse';
import { StepUp } from '../services/step-up';
import { Ui } from '../services/ui';
import { ZonesStore } from '../services/zones-store';
import { Activity } from './activity';
import { ICONS, IconName } from './icons';

/** The sections; primary ones are on the phone's bottom bar, the others behind More. */
const SECTIONS: { path: string; label: string; icon: IconName; primary: boolean }[] = [
  { path: '/zones', label: 'Zones', icon: 'zones', primary: true },
  { path: '/dhcp', label: 'Devices', icon: 'devices', primary: true },
  { path: '/blacklist', label: 'Blocklist', icon: 'blocklist', primary: true },
  { path: '/logs', label: 'Logs', icon: 'logs', primary: true },
  { path: '/proxy', label: 'Proxy', icon: 'proxy', primary: false },
  { path: '/stats', label: 'Statistics', icon: 'stats', primary: false },
  { path: '/geo', label: 'Traffic map', icon: 'map', primary: false },
  { path: '/audit', label: 'Domain check', icon: 'audit', primary: false },
];

@Component({
  selector: 'app-shell',
  imports: [FormsModule, RouterLink, RouterLinkActive, RouterOutlet, Activity],
  templateUrl: './shell.html',
})
export class Shell implements AfterViewInit {
  ui = inject(Ui);
  stepUp = inject(StepUp);
  code = '';
  store = inject(ZonesStore);
  private auth = inject(Auth);
  private api = inject(Api);
  private router = inject(Router);
  private dlg = viewChild.required<ElementRef<HTMLDialogElement>>('dlg');
  private stepDlg = viewChild.required<ElementRef<HTMLDialogElement>>('step');
  private nzDlg = viewChild.required<ElementRef<HTMLDialogElement>>('nz');
  private revDlg = viewChild.required<ElementRef<HTMLDialogElement>>('rev');
  private sheetDlg = viewChild.required<ElementRef<HTMLDialogElement>>('sheet');
  private noticeEl = viewChild.required<ElementRef<HTMLElement>>('notice');
  readonly sections = SECTIONS;
  readonly icons = ICONS;
  superuser = signal(false); // the Django admin link is for superusers
  newZone = '';
  cidr = '';

  private url = toSignal(
    this.router.events.pipe(filter(e => e instanceof NavigationEnd), map(() => this.router.url)),
    { initialValue: this.router.url },
  );
  inZones = () => this.url().startsWith('/zones');

  constructor() {
    this.store.load();
    this.api.invoke(meRetrieve).then(m => { this.superuser.set(m.is_superuser); this.store.defaultZone.set(m.default_zone); }).catch(() => {});
    // A stale error from one page shouldn't follow you to the next.
    this.router.events.pipe(filter(e => e instanceof NavigationEnd)).subscribe(() => { this.ui.dismiss(); this.sheetDlg().nativeElement.close(); });
    // an error a page set by hand (not through ui.run) is shown like the others
    effect(() => { const e = this.ui.error(); if (e && this.ui.notice()?.text !== e) this.ui.notice.set({ kind: 'error', text: e }); });
    // the notice is a popover: in the top layer, so it shows above an open dialog too (shown again to stay above one opened later)
    effect(() => {
      const el = this.noticeEl().nativeElement;
      if (el.matches(':popover-open')) el.hidePopover();
      if (this.ui.notice()) el.showPopover();
    });
  }

  ngAfterViewInit() { this.ui.dlg = this.dlg().nativeElement; this.stepUp.dlg = this.stepDlg().nativeElement; }
  async confirmCode() { await this.stepUp.code(this.code); this.code = ''; }

  openZone() { this.newZone = ''; this.ui.error.set(''); this.nzDlg().nativeElement.showModal(); }
  async addZone() { if (await this.store.add(this.newZone)) { this.newZone = ''; this.nzDlg().nativeElement.close(); } }
  zonePreview = () => cidrToZone(this.cidr);
  openReverse() { this.cidr = ''; this.ui.error.set(''); this.revDlg().nativeElement.showModal(); }
  async addReverse() { if (await this.store.addReverse(this.cidr)) this.revDlg().nativeElement.close(); }
  /** The admin has no password form of its own: a one-use ticket, issued only to a logged-in GUI session, starts it. */
  openAdmin() {
    return this.ui.run(async () => {
      const grant = await this.stepUp.request('admin', 'Open the advanced admin', 'Open admin'); // the admin can remove anybody's second factor: prove yours first
      if (grant === null) return;
      const { ticket } = await this.api.invoke(adminTicketCreate, { 'X-MFA-Grant': grant || undefined });
      const f = Object.assign(document.createElement('form'), { method: 'post', action: '/admin/sso/', target: '_blank' });
      f.append(Object.assign(document.createElement('input'), { type: 'hidden', name: 'ticket', value: ticket }));
      document.body.append(f); f.submit(); f.remove();
    });
  }
  logout() { this.auth.logout(); this.router.navigateByUrl('/login'); }
  /** the skip link moves focus, not only the scroll position */
  skip(ev: Event) { ev.preventDefault(); document.getElementById('main')?.focus(); }
}
