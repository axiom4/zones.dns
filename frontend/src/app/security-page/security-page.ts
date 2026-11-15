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

  constructor() { this.load(); }
  load() { return this.ui.run(async () => this.st.set(await this.api.invoke(mfaRetrieve))); }
  added() { this.adding.set(false); this.load(); }

  removeTotp() {
    this.ui.ask('Remove the authenticator app?', 'Future sign-ins will no longer accept its codes.', () =>
      this.ui.run(async () => {
        const grant = await this.stepUp.request('mfa-change'); // a second factor proves it is really you, not a stolen session
        if (grant === null) return;
        await this.api.invoke(mfaTotpRemoveDestroy, { 'X-MFA-Grant': grant || undefined }); await this.load();
      }));
  }
  removePasskey(p: PasskeyInfo) {
    this.ui.ask(`Remove the passkey ${p.name}?`, 'You will no longer be able to use it to sign in. Remove it from your device too if you like.', () =>
      this.ui.run(async () => {
        const grant = await this.stepUp.request('mfa-change');
        if (grant === null) return;
        await this.api.invoke(mfaPasskeyRemoveDestroy, { id: p.id, 'X-MFA-Grant': grant || undefined }); await this.load();
      }));
  }
}
