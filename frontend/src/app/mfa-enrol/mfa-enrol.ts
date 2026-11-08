import { Component, inject, input, output, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import qrcode from 'qrcode-generator';
import { MfaClient } from '../services/mfa-client';
import { Ui } from '../services/ui';
import { createPasskey, passkeyError, passkeysSupported } from '../services/webauthn';

/** Adds a second factor. During login `ticket` comes from the password step; on the Security page it is empty. */
@Component({
  selector: 'app-mfa-enrol',
  imports: [FormsModule],
  templateUrl: './mfa-enrol.html',
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
