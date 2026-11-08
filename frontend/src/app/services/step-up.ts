import { Injectable, inject, signal } from '@angular/core';
import { Api } from '../api/api';
import { mfaRetrieve } from '../api/functions';
import { MfaClient } from './mfa-client';
import { passkeyError, passkeysSupported, usePasskey } from './webauthn';

interface Pending { scope: string; totp: boolean; passkey: boolean; resolve: (grant: string | null) => void }

/**
 * Asks the signed-in user for a second factor before a dangerous action (deleting a zone). No user name or password:
 * the user is already signed in, so a code or a passkey is enough. The answer is a one-use grant (2 minutes) for that action only.
 */
@Injectable({ providedIn: 'root' })
export class StepUp {
  private api = inject(Api);
  private mfa = inject(MfaClient);

  pending = signal<Pending | null>(null);
  error = signal('');
  busy = signal(false);
  dlg?: HTMLDialogElement; // registered by the shell

  /** The grant for `scope`; '' when the user has no second factor (nothing to ask); null when they cancel. */
  async request(scope: string): Promise<string | null> {
    const s = await this.api.invoke(mfaRetrieve);
    if (!s.totp && !s.passkeys.length) return '';
    return new Promise(resolve => {
      this.error.set('');
      this.pending.set({ scope, totp: s.totp, passkey: s.passkeys.length > 0 && passkeysSupported(), resolve });
      this.dlg?.showModal();
    });
  }

  async code(code: string) {
    await this.attempt(p => this.mfa.call('stepup-totp', { scope: p.scope, code }));
  }

  async passkey() {
    await this.attempt(async p => {
      const { options } = await this.mfa.call('stepup-passkey-options', { scope: p.scope });
      let credential: unknown;
      try { credential = await usePasskey(options); } catch (e) { throw { message: passkeyError(e) }; }
      return this.mfa.call('stepup-passkey-verify', { scope: p.scope, credential });
    });
  }

  cancel() { this.finish(null); }
  /** The dialog was closed (button, Esc, click outside) without an answer. */
  closed() { this.finish(null); }

  private async attempt(f: (p: Pending) => Promise<{ grant: string }>) {
    const p = this.pending();
    if (!p || this.busy()) return;
    this.busy.set(true); this.error.set('');
    try {
      const { grant } = await f(p);
      this.finish(grant);
    } catch (e: any) {
      this.error.set(e.error?.detail ?? e.message ?? 'Confirmation failed.');
    } finally { this.busy.set(false); }
  }

  private finish(grant: string | null) {
    const p = this.pending();
    this.pending.set(null);
    this.dlg?.open && this.dlg.close();
    p?.resolve(grant);
  }
}
