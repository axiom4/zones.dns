import { Component, inject, signal } from '@angular/core';
import { Api } from '../api/api';
import { mfaPasskeyRemoveDestroy, mfaRetrieve, mfaTotpRemoveDestroy } from '../api/functions';
import { MfaStatus, PasskeyInfo } from '../api/models';
import { MfaEnrol } from '../mfa-enrol/mfa-enrol';
import { StepUp } from '../services/step-up';
import { Ui } from '../services/ui';

@Component({
  selector: 'app-security-page',
  imports: [MfaEnrol],
  templateUrl: './security-page.html',
})
export class SecurityPage {
  private api = inject(Api);
  private ui = inject(Ui);
  private stepUp = inject(StepUp);
  st = signal<MfaStatus | null>(null);
  adding = signal(false);
  start = signal<'totp' | ''>(''); // "Set up" on the app row goes straight to its QR code

  constructor() { this.load(); }
  load() { return this.ui.run(async () => this.st.set(await this.api.invoke(mfaRetrieve))); }
  toggleAdd() { this.start.set(''); this.adding.set(!this.adding()); }
  open(start: 'totp' | '') { this.start.set(start); this.adding.set(false); setTimeout(() => this.adding.set(true)); } // re-created, so start applies again
  async added(kind: 'totp' | 'passkey') {
    this.adding.set(false);
    await this.load();
    this.ui.toast(kind === 'totp' ? 'Authenticator app turned on' : 'Passkey added');
  }
  /** The only factor left, when one is mandatory: removing it is refused, so the button says why instead. */
  last = (s: MfaStatus) => s.required && (s.totp ? 1 : 0) + s.passkeys.length === 1;
  day = (iso: string) => new Date(iso).toLocaleDateString(undefined, { dateStyle: 'medium' });

  removeTotp() {
    this.ui.ask('Remove the authenticator app?', 'Future sign-ins will no longer accept its codes.', () =>
      this.ui.run(async () => {
        const grant = await this.stepUp.request('mfa-change', 'Remove the authenticator app', 'Remove app'); // a second factor proves it is really you, not a stolen session
        if (grant === null) return;
        await this.api.invoke(mfaTotpRemoveDestroy, { 'X-MFA-Grant': grant || undefined }); await this.load();
        this.ui.toast('Authenticator app removed');
      }), 'Remove app');
  }
  removePasskey(p: PasskeyInfo) {
    this.ui.ask(`Remove the passkey ${p.name}?`, 'You will no longer be able to sign in with it. You can also delete it from your device.', () =>
      this.ui.run(async () => {
        const grant = await this.stepUp.request('mfa-change', `Remove the passkey ${p.name}`, 'Remove passkey');
        if (grant === null) return;
        await this.api.invoke(mfaPasskeyRemoveDestroy, { id: p.id, 'X-MFA-Grant': grant || undefined }); await this.load();
        this.ui.toast(`Removed the passkey ${p.name}`);
      }), 'Remove passkey');
  }
}
