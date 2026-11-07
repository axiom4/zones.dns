import { HttpInterceptorFn } from '@angular/common/http';
import { CanActivateFn, Router } from '@angular/router';
import { Injectable, inject, signal } from '@angular/core';
import { Api } from './api/api';
import { tokenCreate, tokenEncryptedCreate } from './api/functions';
import { LoginResult } from './api/models';
import { LoginError } from './login-crypto';
import { Secure } from './secure';

export interface LoginStep { mfa: 'verify' | 'setup'; ticket: string; methods: string[] }

@Injectable({ providedIn: 'root' })
export class Auth {
  private api = inject(Api);
  token = signal(localStorage.getItem('token'));

  private secure = inject(Secure);

  /** Password step. Returns null when logged in, or the second step to complete (see mfa-enrol.ts / login.ts). */
  async login(username: string, password: string): Promise<LoginStep | null> {
    this.logout(); // a stale token must not ride along with the login requests
    const r = await this.secure.exchange<LoginResult>(p => this.api.invoke(tokenEncryptedCreate, { body: { p } }), { u: username, p: password })
      ?? await this.plainLogin(username, password);
    if (r.token) { this.accept(r.token); return null; }
    if (!r.mfa || !r.ticket) throw new LoginError('Invalid response from the server.');
    return { mfa: r.mfa, ticket: r.ticket, methods: r.methods ?? [] };
  }

  accept(token: string) {
    localStorage.setItem('token', token);
    this.token.set(token);
  }

  private async plainLogin(username: string, password: string): Promise<LoginResult> {
    try {
      return await this.api.invoke(tokenCreate, { body: { username, password } });
    } catch (e: any) {
      throw new LoginError(e.error?.detail ?? 'Wrong credentials.');
    }
  }

  logout() { localStorage.removeItem('token'); this.token.set(null); }
}

export const authInterceptor: HttpInterceptorFn = (req, next) => {
  const t = inject(Auth).token();
  return next(t ? req.clone({ setHeaders: { Authorization: `Token ${t}` } }) : req);
};

export const authGuard: CanActivateFn = () => inject(Auth).token() ? true : inject(Router).parseUrl('/login');
