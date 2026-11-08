import { Injectable, inject } from '@angular/core';
import { Api } from '../api/api';
import { mfaEncryptedCreate, mfaPasskeyOptionsCreate, mfaPasskeyRegisterCreate, mfaPasskeyRegisterOptionsCreate, mfaPasskeyVerifyCreate, mfaStepupPasskeyOptionsCreate, mfaStepupPasskeyVerifyCreate, mfaStepupTotpCreate, mfaTotpConfirmCreate, mfaTotpCreate, mfaTotpSetupCreate } from '../api/functions';
import { Secure } from './secure';

const PLAIN = {
  'totp': mfaTotpCreate, 'passkey-options': mfaPasskeyOptionsCreate, 'passkey-verify': mfaPasskeyVerifyCreate, 'totp-setup': mfaTotpSetupCreate,
  'totp-confirm': mfaTotpConfirmCreate, 'passkey-register-options': mfaPasskeyRegisterOptionsCreate, 'passkey-register': mfaPasskeyRegisterCreate,
  'stepup-totp': mfaStepupTotpCreate, 'stepup-passkey-options': mfaStepupPasskeyOptionsCreate, 'stepup-passkey-verify': mfaStepupPasskeyVerifyCreate,
} as const;
export type MfaAction = keyof typeof PLAIN;

/** Second-factor steps. Inside the encrypted channel whenever the server has one (tickets, codes, passkey data never travel readable). */
@Injectable({ providedIn: 'root' })
export class MfaClient {
  private api = inject(Api);
  private secure = inject(Secure);

  async call<T = any>(action: MfaAction, data: object): Promise<T> {
    const r = await this.secure.exchange<T>(p => this.api.invoke(mfaEncryptedCreate, { body: { p } }), { a: action, d: data });
    return r ?? this.api.invoke(PLAIN[action] as any, { body: data }) as Promise<T>;
  }
}
