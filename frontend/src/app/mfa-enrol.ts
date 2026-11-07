import { Component, inject, input, output, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import qrcode from 'qrcode-generator';
import { MfaClient } from './mfa-client';
import { Ui } from './ui';
import { createPasskey, passkeyError, passkeysSupported } from './webauthn';

/** Adds a second factor. During login `ticket` comes from the password step; on the Security page it is empty. */
@Component({
  selector: 'app-mfa-enrol',
  imports: [FormsModule],
  template: `
    @if (mode() === 'choose') {
      <div class="choices">
        <button type="button" class="choice" (click)="startTotp()">
          <b>Authenticator app</b>
          <span class="soft">6-digit code from Google Authenticator, 1Password, Authy…</span>
        </button>
        <button type="button" class="choice" (click)="addPasskey()" [disabled]="!supported">
          <b>Passkey</b>
          <span class="soft">{{ supported ? 'Fingerprint, face, PIN or security key.' : 'Not supported by this browser.' }}</span>
        </button>
      </div>
    } @else {
      <form (ngSubmit)="confirmTotp()" class="totp">
        <p class="soft">1. Scan the code with your authenticator app.</p>
        @if (qr()) { <img class="qr" [src]="qr()" width="176" height="176" alt="QR code for the authenticator app"> }
        <details><summary class="soft">Can't scan it?</summary><p class="soft">Enter this key by hand: <code>{{ secret() }}</code></p></details>
        <label>2. Type the code the app shows <input name="c" [(ngModel)]="code" inputmode="numeric" autocomplete="one-time-code" maxlength="7" required></label>
        <div class="actions">
          <button type="button" class="ghost" (click)="mode.set('choose')">Back</button>
          <button class="primary">Activate</button>
        </div>
      </form>
    }`,
})
export class MfaEnrol {
  private mfa = inject(MfaClient);
  private ui = inject(Ui);
  ticket = input('');
  done = output<string>(); // API token
  mode = signal<'choose' | 'totp'>('choose');
  secret = signal('');
  qr = signal('');
  code = '';
  supported = passkeysSupported();

  startTotp() {
    return this.ui.run(async () => {
      const r = await this.mfa.call('totp-setup', { ticket: this.ticket() });
      const q = qrcode(0, 'M'); q.addData(r.uri); q.make();
      this.secret.set(r.secret); this.qr.set(q.createDataURL(5, 8)); this.code = ''; this.mode.set('totp');
    });
  }

  confirmTotp() {
    return this.ui.run(async () => this.done.emit((await this.mfa.call('totp-confirm', { ticket: this.ticket(), code: this.code })).token));
  }

  addPasskey() {
    return this.ui.run(async () => {
      const { options } = await this.mfa.call('passkey-register-options', { ticket: this.ticket() });
      let credential: unknown;
      try { credential = await createPasskey(options); } catch (e) { throw { message: passkeyError(e) }; }
      this.done.emit((await this.mfa.call('passkey-register', { ticket: this.ticket(), credential, name: deviceName() })).token);
    });
  }
}

function deviceName() {
  const ua = navigator.userAgent;
  const os = /Mac/.test(ua) ? 'Mac' : /Windows/.test(ua) ? 'Windows' : /iPhone|iPad/.test(ua) ? 'iOS' : /Android/.test(ua) ? 'Android' : /Linux/.test(ua) ? 'Linux' : 'Device';
  return `${os} · ${new Date().toLocaleDateString()}`;
}
