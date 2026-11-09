// PEM / DER formats (PKCS#1, PKCS#8, SPKI, SEC1), delegated to OpenSSL
// through node:crypto.
import { createPrivateKey, createPublicKey, type KeyObject } from 'node:crypto';
import { InvalidPassphraseError, KeyEncryptedError, KeyParseError, UnsupportedError } from '../errors';
import { keyTypeOf } from '../internal/components';
import { hasPassphrase, passphraseBytes } from '../internal/passphrase';
import { parsePem } from '../internal/pem';
import type {
  KeyType,
  Passphrase,
  PrivateKeyDerFormat,
  PublicKeyDerFormat,
} from '../types';

export const PUBLIC_PEM_LABELS = ['PUBLIC KEY', 'RSA PUBLIC KEY'];
export const PRIVATE_PEM_LABELS = ['PRIVATE KEY', 'ENCRYPTED PRIVATE KEY', 'RSA PRIVATE KEY', 'EC PRIVATE KEY'];

const DEFAULT_PEM_CIPHER = 'aes-256-cbc';

function checked(keyObject: KeyObject): KeyObject {
  keyTypeOf(keyObject);
  return keyObject;
}

export function parsePemPublic(text: string, expected?: PublicKeyDerFormat): KeyObject {
  const pem = parsePem(text);
  const format: PublicKeyDerFormat | undefined =
    pem.label === 'PUBLIC KEY' ? 'spki' : pem.label === 'RSA PUBLIC KEY' ? 'pkcs1' : undefined;
  if (!format) throw new KeyParseError(`Not a public key PEM block: ${pem.label}`);
  if (expected && expected !== format) throw new KeyParseError(`Expected a ${expected} public key`);
  return parseDerPublic(pem.body, format);
}

function isPrivateDer(der: Buffer): boolean {
  try {
    parseDerPrivate(der);
    return true;
  } catch (error) {
    return error instanceof KeyEncryptedError;
  }
}

export function parseDerPublic(der: Buffer, format?: PublicKeyDerFormat): KeyObject {
  // createPublicKey() would silently derive the public key from a private one.
  if (isPrivateDer(der)) {
    throw new KeyParseError('Expected a public key but got a private key; use parsePrivateKey()');
  }
  const formats: PublicKeyDerFormat[] = format ? [format] : ['spki', 'pkcs1'];
  let lastError: unknown;
  for (const type of formats) {
    try {
      return checked(createPublicKey({ key: der, format: 'der', type }));
    } catch (error) {
      if (error instanceof UnsupportedError) throw error;
      lastError = error;
    }
  }
  throw new KeyParseError('Invalid public key data', { cause: lastError });
}

const PRIVATE_LABEL_FORMATS: Record<string, PrivateKeyDerFormat> = {
  'PRIVATE KEY': 'pkcs8',
  'ENCRYPTED PRIVATE KEY': 'pkcs8',
  'RSA PRIVATE KEY': 'pkcs1',
  'EC PRIVATE KEY': 'sec1',
};

export function parsePemPrivate(text: string, passphrase?: Passphrase, expected?: PrivateKeyDerFormat): KeyObject {
  const pem = parsePem(text);
  const format = PRIVATE_LABEL_FORMATS[pem.label];
  if (!format) throw new KeyParseError(`Not a private key PEM block: ${pem.label}`);
  if (expected && expected !== format) throw new KeyParseError(`Expected a ${expected} private key`);

  const isEncrypted =
    pem.label === 'ENCRYPTED PRIVATE KEY' || /ENCRYPTED/i.test(pem.headers['proc-type'] ?? '');
  if (isEncrypted && !hasPassphrase(passphrase)) throw new KeyEncryptedError();

  // Re-serialize only the block we parsed so that surrounding text is ignored.
  const start = text.indexOf(`-----BEGIN ${pem.label}-----`);
  const endMarker = `-----END ${pem.label}-----`;
  const block = text.slice(start, text.indexOf(endMarker, start) + endMarker.length) + '\n';
  try {
    return checked(
      createPrivateKey({
        key: block,
        format: 'pem',
        ...(isEncrypted ? { passphrase: passphraseBytes(passphrase) } : {}),
      }),
    );
  } catch (cause) {
    if (cause instanceof UnsupportedError) throw cause;
    if (isEncrypted) throw new InvalidPassphraseError(undefined, { cause });
    throw new KeyParseError('Invalid private key data', { cause });
  }
}

/** EncryptedPrivateKeyInfo starts with SEQUENCE { SEQUENCE { OID ...; PrivateKeyInfo with INTEGER. */
function isEncryptedPkcs8(der: Buffer): boolean {
  if (der[0] !== 0x30 || der.length < 4) return false;
  const lengthByte = der[1] as number;
  const contentStart = lengthByte & 0x80 ? 2 + (lengthByte & 0x7f) : 2;
  return der[contentStart] === 0x30;
}

export function parseDerPrivate(der: Buffer, passphrase?: Passphrase, format?: PrivateKeyDerFormat): KeyObject {
  const formats: PrivateKeyDerFormat[] = format ? [format] : ['pkcs8', 'pkcs1', 'sec1'];
  let lastError: unknown;
  for (const type of formats) {
    try {
      return checked(
        createPrivateKey({
          key: der,
          format: 'der',
          type,
          ...(hasPassphrase(passphrase) && type === 'pkcs8' ? { passphrase: passphraseBytes(passphrase) } : {}),
        }),
      );
    } catch (error) {
      if (error instanceof UnsupportedError) throw error;
      if ((error as NodeJS.ErrnoException).code === 'ERR_MISSING_PASSPHRASE') throw new KeyEncryptedError();
      if (hasPassphrase(passphrase) && type === 'pkcs8' && isEncryptedPkcs8(der)) {
        throw new InvalidPassphraseError(undefined, { cause: error });
      }
      lastError = error;
    }
  }
  throw new KeyParseError('Invalid private key data', { cause: lastError });
}

function assertFormatFor(type: KeyType, format: string): void {
  if (format === 'pkcs1' && type !== 'rsa') {
    throw new UnsupportedError(`The pkcs1 format only supports RSA keys, not ${type}`);
  }
  if (format === 'sec1' && type !== 'ecdsa') {
    throw new UnsupportedError(`The sec1 format only supports ECDSA keys, not ${type}`);
  }
}

export function exportPublic(keyObject: KeyObject, format: PublicKeyDerFormat, encoding: 'pem'): string;
export function exportPublic(keyObject: KeyObject, format: PublicKeyDerFormat, encoding: 'der'): Buffer;
export function exportPublic(keyObject: KeyObject, format: PublicKeyDerFormat, encoding: 'pem' | 'der'): string | Buffer {
  assertFormatFor(keyTypeOf(keyObject), format);
  return keyObject.export({ type: format, format: encoding as 'pem' });
}

export interface PemPrivateOptions {
  passphrase?: Passphrase;
  cipher?: string;
}

export function exportPrivate(
  keyObject: KeyObject,
  format: PrivateKeyDerFormat,
  encoding: 'pem',
  options?: PemPrivateOptions,
): string;
export function exportPrivate(
  keyObject: KeyObject,
  format: PrivateKeyDerFormat,
  encoding: 'der',
  options?: PemPrivateOptions,
): Buffer;
export function exportPrivate(
  keyObject: KeyObject,
  format: PrivateKeyDerFormat,
  encoding: 'pem' | 'der',
  options: PemPrivateOptions = {},
): string | Buffer {
  assertFormatFor(keyTypeOf(keyObject), format);
  const { passphrase } = options;
  if (passphrase !== undefined && passphrase.length === 0) throw new RangeError('passphrase must not be empty');
  if (passphrase !== undefined && encoding === 'der' && format !== 'pkcs8') {
    throw new UnsupportedError(`Encrypted DER output is only supported for pkcs8, not ${format}`);
  }
  try {
    return keyObject.export({
      type: format,
      format: encoding as 'pem',
      ...(passphrase !== undefined
        ? { cipher: options.cipher ?? DEFAULT_PEM_CIPHER, passphrase: passphraseBytes(passphrase) }
        : {}),
    });
  } catch (cause) {
    throw new UnsupportedError(`Could not export key as ${format}`, { cause });
  }
}
