import { CanActivateFn, Router } from '@angular/router';
import { Injectable, inject, signal } from '@angular/core';
import { Api } from '../api/api';
import { logoutCreate, tokenCreate, tokenEncryptedCreate } from '../api/functions';
import { LoginResult } from '../api/models';
import { LoginError } from '../lib/login-crypto';
import { Secure } from './secure';

export interface LoginStep { mfa: 'verify' | 'setup'; ticket: string; methods: string[] }

@Injectable({ providedIn: 'root' })
export class Auth {
  private api = inject(Api);
  /** The token itself is in an HttpOnly cookie the page cannot read (an injected script could not take it away); this only says whether
   * there is a session, for the route guard. The server stays the judge: a 401 sends back to the login. */
  signedIn = signal(localStorage.getItem('signedIn') === '1');

  constructor() { localStorage.removeItem('token'); } // left by older versions, which kept the token itself here

  private secure = inject(Secure);

  /** Password step. Returns null when logged in, or the second step to complete (see mfa-enrol.ts / login.ts). */
  async login(username: string, password: string): Promise<LoginStep | null> {
    await this.logout(); // a stale session must not ride along with the login requests
    const r = await this.secure.exchange<LoginResult>(p => this.api.invoke(tokenEncryptedCreate, { body: { p } }), { u: username, p: password })
      ?? await this.plainLogin(username, password);
    if (r.token) { this.accept(); return null; }
    if (!r.mfa || !r.ticket) throw new LoginError('Invalid response from the server.');
    return { mfa: r.mfa, ticket: r.ticket, methods: r.methods ?? [] };
  }

  /** The sign-in finished: the server has set the cookie. */
  accept() {
    localStorage.setItem('signedIn', '1');
    this.signedIn.set(true);
  }

  private async plainLogin(username: string, password: string): Promise<LoginResult> {
    try {
      return await this.api.invoke(tokenCreate, { body: { username, password } });
    } catch (e: any) {
      throw new LoginError(e.error?.detail ?? 'Wrong credentials.');
    }
  }

  /** Ends the session on the server too (only it can delete the HttpOnly cookie, and the token stops working). */
  async logout() {
    localStorage.removeItem('signedIn');
    this.signedIn.set(false);
    try { await this.api.invoke(logoutCreate); } catch { /* offline: the cookie expires by itself */ }
  }
}

export const authGuard: CanActivateFn = () => inject(Auth).signedIn() ? true : inject(Router).parseUrl('/login');
