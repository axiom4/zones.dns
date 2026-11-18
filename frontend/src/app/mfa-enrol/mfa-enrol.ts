import { Component, ElementRef, Injector, afterNextRender, computed, inject, input, output, signal, viewChild } from '@angular/core';
import { FormsModule } from '@angular/forms';
import qrcode from 'qrcode-generator';
import { MfaClient } from '../services/mfa-client';
import { StepUp } from '../services/step-up';
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
  private stepUp = inject(StepUp);
  ticket = input('');
  start = input<'totp' | ''>(''); // 'totp': skip the choice and show the QR code at once
  done = output<'totp' | 'passkey'>(); // the factor is stored (at sign-in: the session cookie is set)
  busy = signal(false);
  copied = signal(false);
  private injector = inject(Injector);
  private codeInput = viewChild<ElementRef<HTMLInputElement>>('codeInput');
  grouped = computed(() => this.secret().replace(/(.{4})(?=.)/g, '$1 ')); // easier to type by hand
  mode = signal<'choose' | 'totp'>('choose');
  secret = signal('');
  qr = signal('');
  code = '';
  supported = passkeysSupported();

  constructor() { afterNextRender(() => { if (this.start() === 'totp') this.startTotp(); }); }

  copy() { navigator.clipboard?.writeText(this.secret()).then(() => this.copied.set(true), () => {}); }

  private async busyRun(f: () => Promise<unknown>) { this.busy.set(true); await this.ui.run(f); this.busy.set(false); }

  startTotp() {
    return this.busyRun(async () => {
      const r = await this.mfa.call('totp-setup', { ticket: this.ticket() });
      const q = qrcode(0, 'M'); q.addData(r.uri); q.make();
      this.secret.set(r.secret); this.qr.set(q.createDataURL(5, 8)); this.code = ''; this.copied.set(false); this.mode.set('totp');
      afterNextRender(() => this.codeInput()?.nativeElement.focus(), { injector: this.injector });
    });
  }

  confirmTotp() {
    return this.busyRun(async () => {
      const grant = await this.grant('Turn on the authenticator app', 'Turn on');
      if (grant === null) return;
      await this.mfa.call('totp-confirm', { ticket: this.ticket(), code: this.code, grant });
      this.done.emit('totp');
    });
  }

  /** On the Security page a factor that exists confirms the new one (step-up); during login there is none yet. null = cancelled. */
  private async grant(what: string, verb: string): Promise<string | null> { return this.ticket() ? '' : this.stepUp.request('mfa-change', what, verb); }

  addPasskey() {
    return this.busyRun(async () => {
      // the browser's passkey prompt first, while the click still counts as a user gesture (Safari asks for one);
      // cancelling the step-up after it leaves a passkey on the device that the server never stored
      const { options } = await this.mfa.call('passkey-register-options', { ticket: this.ticket() });
      let credential: unknown;
      try { credential = await createPasskey(options); } catch (e) { throw { message: passkeyError(e) }; }
      const grant = await this.grant('Add the passkey', 'Add passkey');
      if (grant === null) return;
      await this.mfa.call('passkey-register', { ticket: this.ticket(), credential, name: deviceName(), grant });
      this.done.emit('passkey');
    });
  }
}

function deviceName() {
  const ua = navigator.userAgent;
  // iOS first: its user agent says "like Mac OS X"
  const os = /iPhone|iPad/.test(ua) ? 'iOS' : /Mac/.test(ua) ? 'Mac' : /Windows/.test(ua) ? 'Windows' : /Android/.test(ua) ? 'Android' : /Linux/.test(ua) ? 'Linux' : 'Device';
  return `${os} · ${new Date().toLocaleDateString()}`;
}
