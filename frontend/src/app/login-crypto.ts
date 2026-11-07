import nacl from 'tweetnacl';

/** Shown to the user as-is. */
export class LoginError extends Error {}

const b64 = (u: Uint8Array) => btoa(String.fromCharCode(...u));
const unb64 = (s: string) => Uint8Array.from(atob(s), c => c.charCodeAt(0));

/**
 * Builds an encrypted packet (login or second-factor step) for the server's public key (Curve25519, NaCl crypto_box).
 * packet = ephemeral public key (32) | nonce (24) | box(JSON {...fields, t, n}); a fresh key pair is used for every login,
 * and the server answers with a box for that same ephemeral key, so only this call can read the reply.
 */
export function seal(serverPublicKeyB64: string, fields: object) {
  const serverPk = unb64(serverPublicKeyB64);
  const eph = nacl.box.keyPair();
  const nonce = nacl.randomBytes(24);
  const n = b64(nacl.randomBytes(16)); // one-time id: lets the server refuse replays and binds the reply to this request
  const msg = new TextEncoder().encode(JSON.stringify({ ...fields, t: Date.now(), n }));
  const box = nacl.box(msg, nonce, serverPk, eph.secretKey);
  const packet = new Uint8Array(32 + 24 + box.length);
  packet.set(eph.publicKey, 0); packet.set(nonce, 32); packet.set(box, 56);

  return {
    packet: b64(packet),
    /** Decrypts the server's reply; the ephemeral secret key is wiped afterwards. */
    open(replyB64: string): Record<string, any> {
      try {
        const raw = unb64(replyB64);
        const plain = nacl.box.open(raw.slice(24), raw.slice(0, 24), serverPk, eph.secretKey);
        const body = plain && JSON.parse(new TextDecoder().decode(plain));
        if (!body || body.n !== n) throw new LoginError('Invalid response from the server.');
        return body;
      } catch (e) {
        throw e instanceof LoginError ? e : new LoginError('Invalid response from the server.');
      } finally { eph.secretKey.fill(0); }
    },
  };
}
