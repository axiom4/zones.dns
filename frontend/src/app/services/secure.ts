import { Injectable, inject } from '@angular/core';
import { LoginKey } from './login-key';
import { LoginError, seal } from '../lib/login-crypto';

/** Sends a request as one packet encrypted to the server's public key (fetched fresh each time) and reads the encrypted reply. */
@Injectable({ providedIn: 'root' })
export class Secure {
  private loginKey = inject(LoginKey);

  /** The decrypted reply, or null when the server has encrypted requests off (the caller then uses the plain endpoint). */
  async exchange<T = Record<string, any>>(send: (packet: string) => Promise<{ p: string }>, fields: object, retry = true): Promise<T | null> {
    const key = await this.loginKey.fetch();
    if (!key) return null;
    const { packet, open } = seal(key, fields);
    let reply: string;
    try {
      reply = (await send(packet)).p;
    } catch (e: any) {
      if (e.error?.p) reply = e.error.p; // errors from the server are encrypted too
      else if (retry && e.status === 400) return this.exchange<T>(send, fields, false); // the server restarted between key and packet: new key now
      else throw new LoginError(e.error?.detail ?? 'Server unreachable.');
    }
    const body = open(reply);
    if (body['error']) throw new LoginError(body['error']);
    return body as T;
  }
}
