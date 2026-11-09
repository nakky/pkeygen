import type { Passphrase } from '../types';

export function hasPassphrase(passphrase: Passphrase | undefined): passphrase is Passphrase {
  return passphrase !== undefined && passphrase.length > 0;
}

export function passphraseBytes(passphrase: Passphrase | undefined): Buffer {
  if (passphrase === undefined) return Buffer.alloc(0);
  return typeof passphrase === 'string' ? Buffer.from(passphrase, 'utf8') : Buffer.from(passphrase);
}
