import { Component, inject, signal } from '@angular/core';
import { Api } from './api/api';
import { mfaPasskeyRemoveDestroy, mfaRetrieve, mfaTotpRemoveDestroy } from './api/functions';
import { MfaStatus, PasskeyInfo } from './api/models';
import { MfaEnrol } from './mfa-enrol';
import { Ui } from './ui';

@Component({
  selector: 'app-security-page',
  imports: [MfaEnrol],
  template: `
    <header>
      <div>
        <h2>Security</h2>
        <p class="soft">Besides your password, signing in needs a second factor: a code from an authenticator app or a passkey.@if (st()?.required) { The second factor is mandatory. }</p>
      </div>
      <div class="actions"><button class="primary" (click)="adding.set(!adding())">{{ adding() ? 'Close' : 'Add a factor' }}</button></div>
    </header>

    @if (adding()) {
      <section class="panel"><h3>Add a factor</h3><app-mfa-enrol (done)="added()" /></section>
    }

    @if (st(); as s) {
      <ul class="records factors">
        <li>
          <span class="fkind">App</span>
          <div class="fbody">
            <b>Authenticator app</b>
            <span class="soft">{{ s.totp ? 'Active: every sign-in needs the 6-digit code.' : 'Not set up.' }}</span>
          </div>
          @if (s.totp) { <button class="mini danger-o" (click)="removeTotp()">Remove</button> }
          @else { <button class="mini" (click)="adding.set(true)">Set up</button> }
        </li>
        @for (p of s.passkeys; track p.id) {
          <li>
            <span class="fkind">Passkey</span>
            <div class="fbody">
              <b>{{ p.name }}</b>
              <span class="soft">Added on {{ p.created.slice(0, 10) }}</span>
            </div>
            <button class="mini danger-o" (click)="removePasskey(p)">Remove</button>
          </li>
        } @empty {
          <li>
            <span class="fkind off">Passkey</span>
            <div class="fbody"><b>No passkey</b><span class="soft">Fingerprint, face, PIN or security key.</span></div>
            <button class="mini" (click)="adding.set(true)">Add</button>
          </li>
        }
      </ul>
      <p class="soft note">If you lose your phone or key, an administrator can reset your factors with <code>python manage.py mfa_reset &lt;user&gt;</code>.</p>
    }`,
})
export class SecurityPage {
  private api = inject(Api);
  private ui = inject(Ui);
  st = signal<MfaStatus | null>(null);
  adding = signal(false);

  constructor() { this.load(); }
  load() { return this.ui.run(async () => this.st.set(await this.api.invoke(mfaRetrieve))); }
  added() { this.adding.set(false); this.load(); }

  removeTotp() {
    this.ui.ask('Remove the authenticator app?', 'Future sign-ins will no longer accept its codes.', () =>
      this.ui.run(async () => { await this.api.invoke(mfaTotpRemoveDestroy); await this.load(); }));
  }
  removePasskey(p: PasskeyInfo) {
    this.ui.ask(`Remove the passkey ${p.name}?`, 'You will no longer be able to use it to sign in. Remove it from your device too if you like.', () =>
      this.ui.run(async () => { await this.api.invoke(mfaPasskeyRemoveDestroy, { id: p.id }); await this.load(); }));
  }
}
