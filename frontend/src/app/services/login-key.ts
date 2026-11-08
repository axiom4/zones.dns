import { Injectable, inject, signal } from '@angular/core';
import { Api } from '../api/api';
import { loginKeyRetrieve } from '../api/functions';
import { LoginError } from '../lib/login-crypto';

/** The server's public key for the encrypted login. It is new after every server restart, so it is always fetched fresh. */
@Injectable({ providedIn: 'root' })
export class LoginKey {
  private api = inject(Api);

  /** True once the server has said it wants encrypted logins (used for the hint on the login screen). */
  active = signal(false);

  /** The public key (base64), or null when the server's encrypted login is off (plain login). */
  async fetch(): Promise<string | null> {
    try {
      const { key } = await this.api.invoke(loginKeyRetrieve);
      this.active.set(true);
      return key;
    } catch (e: any) {
      this.active.set(false);
      if (e.status === 404) return null;
      throw new LoginError('Cannot reach the server to sign in.');
    }
  }
}
