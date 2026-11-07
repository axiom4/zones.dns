import { Component, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { Router } from '@angular/router';
import { Auth, LoginStep } from './auth';
import { MfaClient } from './mfa-client';
import { MfaEnrol } from './mfa-enrol';
import { passkeyError, usePasskey } from './webauthn';
import { LoginKey } from './login-key';
import { LoginError } from './login-crypto';
import { Ui } from './ui';

@Component({
  selector: 'app-login',
  imports: [FormsModule, MfaEnrol],
  template: `
    <div class="welcome">
      <section class="hero">
        <p class="brand"><img src="logo.svg" alt="" width="34" height="34"><i>Zones<span>.dns</span></i></p>
        <h1>Your network's names, under control.</h1>
        <p>Create zones and records in seconds. Anything that isn't yours is resolved upstream, no thinking required.</p>
      </section>
      @switch (step()?.mfa) {
        @case ('verify') {
          <form (ngSubmit)="verifyTotp()">
            <h2>Two-step verification</h2>
            <p class="soft">Confirm it's you with a second factor.</p>
            @if (step()!.methods.includes('passkey')) {
              <button type="button" class="primary big" (click)="verifyPasskey()">Use your passkey</button>
            }
            @if (step()!.methods.includes('totp')) {
              <label>Authenticator app code <input name="c" [(ngModel)]="code" inputmode="numeric" autocomplete="one-time-code" maxlength="7" [attr.autofocus]="step()!.methods.includes('passkey') ? null : ''"></label>
              <button class="primary big" [class.ghost]="step()!.methods.includes('passkey')">Verify code</button>
            }
            @if (ui.error()) { <p class="error" role="alert">{{ ui.error() }}</p> }
            <button type="button" class="link" (click)="back()">Back to sign in</button>
          </form>
        }
        @case ('setup') {
          <div class="form">
            <h2>Protect your account</h2>
            <p class="soft">A second factor is required to use the app. Choose how you want to confirm future sign-ins.</p>
            <app-mfa-enrol [ticket]="step()!.ticket" (done)="finish($event)" />
            @if (ui.error()) { <p class="error" role="alert">{{ ui.error() }}</p> }
            <button type="button" class="link" (click)="back()">Back to sign in</button>
          </div>
        }
        @default {
          <form (ngSubmit)="login()">
            <h2>Welcome back</h2>
            @if (key.active()) { <p class="soft secure">Encrypted sign-in: your credentials never travel in clear text.</p> }
            <label>Username <input name="u" [(ngModel)]="user" autocomplete="username" required autofocus></label>
            <label>Password <input name="p" [(ngModel)]="pass" type="password" autocomplete="current-password" required></label>
            @if (ui.error()) { <p class="error" role="alert">{{ ui.error() }}</p> }
            <button class="primary big">Sign in</button>
          </form>
        }
      }
    </div>`,
})
export class Login {
  ui = inject(Ui);
  key = inject(LoginKey);
  private auth = inject(Auth);
  private mfa = inject(MfaClient);
  private router = inject(Router);
  user = ''; pass = ''; code = '';
  step = signal<LoginStep | null>(null);

  constructor() {
    this.ui.error.set('');
    this.key.fetch().catch(() => {}); // only to show the lock hint
  }

  async login() {
    try { this.step.set(await this.auth.login(this.user, this.pass)); } catch (e) { this.ui.error.set(e instanceof LoginError ? e.message : 'Sign-in failed.'); return; }
    this.pass = ''; this.ui.error.set('');
    if (!this.step()) this.router.navigateByUrl('/');
  }

  verifyTotp() {
    return this.ui.run(async () => this.finish((await this.mfa.call('totp', { ticket: this.step()!.ticket, code: this.code })).token));
  }

  verifyPasskey() {
    return this.ui.run(async () => {
      const ticket = this.step()!.ticket;
      const { options } = await this.mfa.call('passkey-options', { ticket });
      let credential: unknown;
      try { credential = await usePasskey(options); } catch (e) { throw { message: passkeyError(e) }; }
      this.finish((await this.mfa.call('passkey-verify', { ticket, credential })).token);
    });
  }

  finish(token: string) { this.auth.accept(token); this.router.navigateByUrl('/'); }
  back() { this.step.set(null); this.code = ''; this.ui.error.set(''); }
}
