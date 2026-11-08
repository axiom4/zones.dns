/** Browser side of passkeys. Options and credentials travel as JSON (PublicKeyCredential.*FromJSON / toJSON). */
const pk = () => PublicKeyCredential as any;

export const passkeysSupported = () =>
  typeof PublicKeyCredential !== 'undefined' && 'parseCreationOptionsFromJSON' in PublicKeyCredential && !!navigator.credentials;

export async function createPasskey(options: unknown): Promise<unknown> {
  const c = await navigator.credentials.create({ publicKey: pk().parseCreationOptionsFromJSON(options) }) as any;
  return c.toJSON();
}

export async function usePasskey(options: unknown): Promise<unknown> {
  const c = await navigator.credentials.get({ publicKey: pk().parseRequestOptionsFromJSON(options) }) as any;
  return c.toJSON();
}

/** The browser's own wording is English and vague; say what happened. */
export function passkeyError(e: any): string {
  if (e?.name === 'NotAllowedError') return 'Cancelled or timed out.';
  if (e?.name === 'InvalidStateError') return 'This passkey is already registered.';
  if (e?.name === 'SecurityError') return 'Passkeys are not available at this address: https or localhost is required.';
  return e?.message ?? 'Passkey failed.';
}
