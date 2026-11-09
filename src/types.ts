export type KeyType = 'rsa' | 'ecdsa' | 'ed25519';

export type EcdsaCurve = 'nistp256' | 'nistp384' | 'nistp521';

/**
 * Text formats a public key can be written in.
 *
 * - `openssh`: single line `ssh-ed25519 AAAA... comment` (authorized_keys / id_xxx.pub)
 * - `rfc4716`: `---- BEGIN SSH2 PUBLIC KEY ----` (also what PuTTY saves as a public key)
 * - `spki`: PEM `-----BEGIN PUBLIC KEY-----` (called PKCS#8 by `ssh-keygen -m PKCS8`)
 * - `pkcs1`: PEM `-----BEGIN RSA PUBLIC KEY-----` (RSA only)
 */
export type PublicKeyFormat = 'openssh' | 'rfc4716' | 'spki' | 'pkcs1';

/**
 * Text formats a private key can be written in.
 *
 * - `openssh`: `-----BEGIN OPENSSH PRIVATE KEY-----`
 * - `pkcs8`: PEM `-----BEGIN PRIVATE KEY-----` / `-----BEGIN ENCRYPTED PRIVATE KEY-----`
 * - `pkcs1`: PEM `-----BEGIN RSA PRIVATE KEY-----` (RSA only)
 * - `sec1`: PEM `-----BEGIN EC PRIVATE KEY-----` (ECDSA only)
 * - `putty`: PuTTY `.ppk`
 */
export type PrivateKeyFormat = 'openssh' | 'pkcs8' | 'pkcs1' | 'sec1' | 'putty';

export type PublicKeyDerFormat = 'spki' | 'pkcs1';
export type PrivateKeyDerFormat = 'pkcs8' | 'pkcs1' | 'sec1';

export type FingerprintAlgorithm = 'sha256' | 'sha512' | 'sha1' | 'md5';

export type Passphrase = string | Uint8Array;

/** Ciphers usable when writing an encrypted `openssh` private key. */
export type OpenSshCipher =
  | 'aes128-ctr'
  | 'aes192-ctr'
  | 'aes256-ctr'
  | 'aes128-cbc'
  | 'aes192-cbc'
  | 'aes256-cbc'
  | 'aes128-gcm@openssh.com'
  | 'aes256-gcm@openssh.com'
  /** Legacy cipher with a 64-bit block size; only use it for compatibility. */
  | '3des-cbc';

export interface PublicKeyWriteOptions {
  /** Overrides the comment stored on the key. */
  comment?: string;
}

export interface PrivateKeyWriteOptions {
  /** Encrypts the output when given. */
  passphrase?: Passphrase;
  /** Overrides the comment stored on the key (`openssh` and `putty` only). */
  comment?: string;
  /** `openssh` only. Defaults to `aes256-ctr`. */
  cipher?: OpenSshCipher;
  /** `openssh` only: bcrypt-pbkdf rounds. Defaults to 16, like ssh-keygen. */
  rounds?: number;
  /** `pkcs8`, `pkcs1` and `sec1` only: OpenSSL cipher name. Defaults to `aes-256-cbc`. */
  pemCipher?: string;
  /**
   * `putty` only. Defaults to 2, which every PuTTY version can read.
   * Version 3 can only be written without a passphrase.
   */
  ppkVersion?: 2 | 3;
}

export interface ParseOptions<F extends string> {
  /** Defaults to `auto`. */
  format?: F | 'auto';
  passphrase?: Passphrase;
}

export type GenerateOptions =
  | { type: 'ed25519'; comment?: string }
  /** `bits` defaults to 3072. */
  | { type: 'rsa'; bits?: number; comment?: string }
  /** `curve` defaults to `nistp256`. */
  | { type: 'ecdsa'; curve?: EcdsaCurve; comment?: string };
