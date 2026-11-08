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
