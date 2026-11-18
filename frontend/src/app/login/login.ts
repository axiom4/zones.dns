import { Component, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { Router } from '@angular/router';
import { Auth, LoginStep } from '../services/auth';
import { MfaClient } from '../services/mfa-client';
import { MfaEnrol } from '../mfa-enrol/mfa-enrol';
import { passkeyError, usePasskey } from '../services/webauthn';
import { LoginKey } from '../services/login-key';
import { LoginError } from '../lib/login-crypto';
import { Ui } from '../services/ui';

@Component({
  selector: 'app-login',
  imports: [FormsModule, MfaEnrol],
  templateUrl: './login.html',
})
export class Login {
  ui = inject(Ui);
  key = inject(LoginKey);
  private auth = inject(Auth);
  private mfa = inject(MfaClient);
  private router = inject(Router);
  user = ''; pass = ''; code = '';
  step = signal<LoginStep | null>(null);
  busy = signal(false);

  constructor() {
    this.ui.error.set('');
    this.key.fetch().catch(() => {}); // only to show the lock hint
  }

  async login() {
    if (this.busy()) return;
    if (!this.user.trim() || !this.pass) { this.ui.error.set('Enter your user name and password.'); return; }
    this.busy.set(true);
    try { this.step.set(await this.auth.login(this.user, this.pass)); } catch (e) {
      this.ui.error.set(e instanceof LoginError ? e.message : 'Sign-in failed: check the user name and password, then try again.');
      this.busy.set(false);
      return;
    }
    this.busy.set(false);
    this.pass = ''; this.ui.error.set('');
    if (!this.step()) this.router.navigateByUrl('/');
    else if (this.step()!.mfa === 'verify' && !this.step()!.methods.includes('passkey')) setTimeout(() => document.getElementById('lg-code')?.focus());
  }

  private async busyRun(f: () => Promise<unknown>) { this.busy.set(true); await this.ui.run(f); this.busy.set(false); }

  verifyTotp() {
    if (!this.code.trim()) { this.ui.error.set('Enter the 6-digit code your authenticator app shows.'); return; }
    return this.busyRun(async () => { await this.mfa.call('totp', { ticket: this.step()!.ticket, code: this.code }); this.finish(); });
  }

  verifyPasskey() {
    return this.busyRun(async () => {
      const ticket = this.step()!.ticket;
      const { options } = await this.mfa.call('passkey-options', { ticket });
      let credential: unknown;
      try { credential = await usePasskey(options); } catch (e) { throw { message: passkeyError(e) }; }
      await this.mfa.call('passkey-verify', { ticket, credential });
      this.finish();
    });
  }

  finish() { this.auth.accept(); this.router.navigateByUrl('/'); }
  back() { this.step.set(null); this.code = ''; this.ui.error.set(''); setTimeout(() => document.getElementById('lg-user')?.focus()); }
}
