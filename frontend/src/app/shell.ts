import { AfterViewInit, Component, ElementRef, inject, signal, viewChild } from '@angular/core';
import { toSignal } from '@angular/core/rxjs-interop';
import { FormsModule } from '@angular/forms';
import { NavigationEnd, Router, RouterLink, RouterLinkActive, RouterOutlet } from '@angular/router';
import { filter, map } from 'rxjs';
import { Api } from './api/api';
import { adminTicketCreate, meRetrieve } from './api/functions';
import { Auth } from './auth';
import { cidrToZone } from './reverse';
import { Ui } from './ui';
import { ZonesStore } from './zones-store';

@Component({
  selector: 'app-shell',
  imports: [FormsModule, RouterLink, RouterLinkActive, RouterOutlet],
  template: `
    <div class="shell">
      <aside>
        <p class="brand"><img src="logo.svg" alt="" width="30" height="30"><i>Zones<span>.dns</span></i></p>
        <div class="tabs">
          <a routerLink="/zones" routerLinkActive="on" [routerLinkActiveOptions]="{ exact: false }">Zones</a>
          <a routerLink="/blacklist" routerLinkActive="on">Blacklist</a>
          <a routerLink="/logs" routerLinkActive="on">Query log</a>
          <a routerLink="/geo" routerLinkActive="on">Geolocation</a>
          <a routerLink="/audit" routerLinkActive="on">Domain audit</a>
          <a routerLink="/stats" routerLinkActive="on">Statistics</a>
          <a routerLink="/security" routerLinkActive="on">Security</a>
        </div>
        @if (inZones()) {
          <nav aria-label="Zones">
            @for (g of store.groups(); track g.title) {
              @if (g.zones.length || g.title === 'Your zones') {
                <p class="label">{{ g.title }}</p>
                @for (z of g.zones; track z.id) {
                  <div class="zone" routerLinkActive="active">
                    <a class="zname" [routerLink]="['/zones', z.id]" [title]="z.cidr ?? ''">{{ z.name }}</a>
                    <button class="icon" (click)="store.del(z)" [attr.aria-label]="'Delete ' + z.name">✕</button>
                  </div>
                } @empty {
                  <p class="soft">No zones yet. Create one below.</p>
                }
              }
            }
          </nav>
          <form class="addzone" (ngSubmit)="addZone()">
            <input name="z" [(ngModel)]="newZone" placeholder="New zone, e.g. corp.lan" autocomplete="off" aria-label="New zone name" required>
            <button class="primary">+</button>
          </form>
          <button class="link small-l" (click)="openReverse()">+ New reverse zone…</button>
        } @else if (inBlacklist()) {
          <nav aria-label="Blacklist">
            <p class="label">Blacklist</p>
            <div class="zone" routerLinkActive="active"><a class="zname" routerLink="/blacklist/manual">Personal blocks</a></div>
            <div class="zone" routerLinkActive="active"><a class="zname" routerLink="/blacklist/lists">Public lists</a></div>
          </nav>
          <div class="grow"></div>
        } @else {
          <div class="grow"></div>
        }
        @if (superuser()) { <button class="link" (click)="openAdmin()">Admin Django ↗</button> }
        <button class="link" (click)="logout()">Sign out</button>
      </aside>

      <main>
        @if (ui.error()) { <p class="error" role="alert">{{ ui.error() }}</p> }
        <router-outlet />
      </main>
    </div>

    <dialog #rev class="confirm" (click)="$event.target === rev ? rev.close() : null">
      <form (ngSubmit)="addReverse()">
        <h3>New reverse zone</h3>
        <p class="soft pl">A reverse zone maps an IP address back to a name (PTR records). Enter the network you want to cover.</p>
        <label class="field">
          <span class="lbl">Network (CIDR)</span>
          <input name="cidr" [(ngModel)]="cidr" placeholder="10.0.0.0/24" autocomplete="off" required aria-describedby="h-cidr">
          <small id="h-cidr" class="help">IPv4: /8, /16 or /24 (e.g. <code>10.0.0.0/24</code>). IPv6: prefixes that are multiples of 4 (e.g. <code>fd00:1234::/48</code>).</small>
          @if (cidr.trim()) {
            <small class="full">Zone: <b>{{ zonePreview() ?? 'worked out by the server' }}</b></small>
          }
        </label>
        @if (ui.error()) { <p class="error" role="alert">{{ ui.error() }}</p> }
        <div class="actions">
          <button type="button" class="ghost" (click)="rev.close()">Cancel</button>
          <button class="primary">Create zone</button>
        </div>
      </form>
    </dialog>

    <dialog #dlg class="confirm" (click)="$event.target === dlg ? dlg.close() : null">
      <h3>{{ ui.box()?.title }}</h3>
      <p class="soft">{{ ui.box()?.text }}</p>
      <div class="actions">
        <button class="ghost" autofocus (click)="dlg.close()">Cancel</button>
        <button class="danger" (click)="ui.yes()">Confirm</button>
      </div>
    </dialog>`,
})
export class Shell implements AfterViewInit {
  ui = inject(Ui);
  store = inject(ZonesStore);
  private auth = inject(Auth);
  private api = inject(Api);
  private router = inject(Router);
  private dlg = viewChild.required<ElementRef<HTMLDialogElement>>('dlg');
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

  ngAfterViewInit() { this.ui.dlg = this.dlg().nativeElement; }

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
