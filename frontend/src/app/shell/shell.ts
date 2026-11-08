import { AfterViewInit, Component, ElementRef, inject, signal, viewChild } from '@angular/core';
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

@Component({
  selector: 'app-shell',
  imports: [FormsModule, RouterLink, RouterLinkActive, RouterOutlet],
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
  private revDlg = viewChild.required<ElementRef<HTMLDialogElement>>('rev');
  superuser = signal(false); // the Django admin link is for superusers
  newZone = '';
  cidr = '';

  private url = toSignal(
    this.router.events.pipe(filter(e => e instanceof NavigationEnd), map(() => this.router.url)),
    { initialValue: this.router.url },
  );
  inZones = () => this.url().startsWith('/zones');
  inBlacklist = () => this.url().startsWith('/blacklist');

  constructor() {
    this.store.load();
    this.api.invoke(meRetrieve).then(m => { this.superuser.set(m.is_superuser); this.store.defaultZone.set(m.default_zone); }).catch(() => {});
    // A stale error from one page shouldn't follow you to the next.
    this.router.events.pipe(filter(e => e instanceof NavigationEnd)).subscribe(() => this.ui.error.set(''));
  }

  ngAfterViewInit() { this.ui.dlg = this.dlg().nativeElement; this.stepUp.dlg = this.stepDlg().nativeElement; }
  async confirmCode() { await this.stepUp.code(this.code); this.code = ''; }

  async addZone() { if (await this.store.add(this.newZone)) this.newZone = ''; }
  zonePreview = () => cidrToZone(this.cidr);
  openReverse() { this.cidr = ''; this.ui.error.set(''); this.revDlg().nativeElement.showModal(); }
  async addReverse() { if (await this.store.addReverse(this.cidr)) this.revDlg().nativeElement.close(); }
  /** The admin has no password form of its own: a one-use ticket, issued only to a logged-in GUI session, starts it. */
  openAdmin() {
    return this.ui.run(async () => {
      const { ticket } = await this.api.invoke(adminTicketCreate);
      const f = Object.assign(document.createElement('form'), { method: 'post', action: '/admin/sso/', target: '_blank' });
      f.append(Object.assign(document.createElement('input'), { type: 'hidden', name: 'ticket', value: ticket }));
      document.body.append(f); f.submit(); f.remove();
    });
  }
  logout() { this.auth.logout(); this.router.navigateByUrl('/login'); }
}
