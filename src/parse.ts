import { createPrivateKey, createPublicKey, KeyObject, type JsonWebKey } from 'node:crypto';
import { KeyParseError, PkeygenError } from './errors';
import { OPENSSH_PEM_LABEL, parseOpenSshPrivate } from './formats/openssh-private';
import {
  parseDerPrivate,
  parseDerPublic,
  parsePemPrivate,
  parsePemPublic,
  PRIVATE_PEM_LABELS,
  PUBLIC_PEM_LABELS,
} from './formats/pem-keys';
import { isPutty, parsePutty } from './formats/putty';
import { isRfc4716, parseRfc4716 } from './formats/rfc4716';
import { decodePublicBlob, parseOpenSshPublic } from './formats/ssh-public';
import { keyTypeOf } from './internal/components';
import { findPemLabel } from './internal/pem';
import { PrivateKey, PublicKey } from './key';
import type { ParseOptions, Passphrase, PrivateKeyFormat, PublicKeyFormat } from './types';

/** Key data: text, binary (DER or SSH blob), a JWK object or a Node.js KeyObject. */
export type KeyInput = string | Uint8Array | JsonWebKey | KeyObject;

type Normalized =
  | { kind: 'text'; text: string }
  | { kind: 'binary'; data: Buffer }
  | { kind: 'jwk'; jwk: JsonWebKey }
  | { kind: 'keyObject'; keyObject: KeyObject };

function normalize(input: KeyInput): Normalized {
  if (input instanceof KeyObject) return { kind: 'keyObject', keyObject: input };
  if (typeof input === 'string') return normalizeText(input);
  if (input instanceof Uint8Array) {
    const data = Buffer.from(input.buffer, input.byteOffset, input.byteLength);
    // DER starts with a SEQUENCE tag and SSH blobs with a length; text keys start with neither.
    if (data.length > 0 && (data[0] === 0x30 || data[0] === 0x00)) return { kind: 'binary', data };
    return normalizeText(data.toString('utf8'));
  }
  if (input !== null && typeof input === 'object' && typeof (input as JsonWebKey).kty === 'string') {
    return { kind: 'jwk', jwk: input };
  }
  throw new TypeError('Key input must be a string, Uint8Array, JWK object or KeyObject');
}

function normalizeText(raw: string): Normalized {
  const text = raw.replace(/^﻿/, '').trim();
  if (text === '') throw new KeyParseError('Key input is empty');
  if (text.startsWith('{')) {
    let jwk: unknown;
    try {
      jwk = JSON.parse(text);
    } catch (cause) {
      throw new KeyParseError('Invalid JWK: not valid JSON', { cause });
    }
    if (jwk === null || typeof jwk !== 'object' || typeof (jwk as JsonWebKey).kty !== 'string') {
      throw new KeyParseError('Invalid JWK: missing "kty"');
    }
    return { kind: 'jwk', jwk: jwk as JsonWebKey };
  }
  return { kind: 'text', text };
}

function jwkIsPrivate(jwk: JsonWebKey): boolean {
  return typeof jwk.d === 'string';
}

function wrapErrors<T>(what: string, fn: () => T): T {
  try {
    return fn();
  } catch (error) {
    if (error instanceof PkeygenError || error instanceof TypeError || error instanceof RangeError) throw error;
    throw new KeyParseError(`Invalid ${what}`, { cause: error });
  }
}

function privateFromJwk(jwk: JsonWebKey): PrivateKey {
  return wrapErrors('JWK private key', () => {
    if (!jwkIsPrivate(jwk)) throw new KeyParseError('JWK does not contain a private key');
    return PrivateKey.fromKeyObject(createPrivateKey({ key: jwk, format: 'jwk' }));
  });
}

function publicFromJwk(jwk: JsonWebKey): PublicKey {
  return wrapErrors('JWK public key', () => {
    // Drop private fields so that createPublicKey accepts private JWKs too.
    const { d, p, q, dp, dq, qi, ...publicJwk } = jwk;
    void [d, p, q, dp, dq, qi];
    return PublicKey.fromKeyObject(createPublicKey({ key: publicJwk, format: 'jwk' }));
  });
}

function detectPrivateFormat(text: string): PrivateKeyFormat | 'pem' | undefined {
  if (isPutty(text)) return 'putty';
  const label = findPemLabel(text);
  if (label === OPENSSH_PEM_LABEL) return 'openssh';
  if (label !== undefined && PRIVATE_PEM_LABELS.includes(label)) return 'pem';
  return undefined;
}

/**
 * Parses a private key. With `format: 'auto'` (the default) the format is
 * detected from the content.
 *
 * @throws KeyEncryptedError when the key is encrypted and no passphrase is given
 * @throws InvalidPassphraseError when the passphrase is wrong
 */
export function parsePrivateKey(input: KeyInput, options: ParseOptions<PrivateKeyFormat> = {}): PrivateKey {
  const format = options.format ?? 'auto';
  const { passphrase } = options;
  const source = normalize(input);

  switch (source.kind) {
    case 'keyObject':
      return PrivateKey.fromKeyObject(source.keyObject);
    case 'jwk':
      return privateFromJwk(source.jwk);
    case 'binary': {
      if (format === 'openssh' || format === 'putty') {
        throw new KeyParseError(`The ${format} format is text, but binary data was given`);
      }
      return PrivateKey.fromKeyObject(
        parseDerPrivate(source.data, passphrase, format === 'auto' ? undefined : format),
      );
    }
    case 'text':
      return parsePrivateText(source.text, format, passphrase);
  }
}

function parsePrivateText(text: string, format: PrivateKeyFormat | 'auto', passphrase?: Passphrase): PrivateKey {
  const detected = detectPrivateFormat(text);
  const effective = format === 'auto' ? detected : format;
  switch (effective) {
    case undefined:
      throw new KeyParseError('Could not detect the private key format');
    case 'openssh': {
      const parsed = parseOpenSshPrivate(text, passphrase);
      return PrivateKey.fromComponents(parsed.components, parsed.comment);
    }
    case 'putty': {
      const parsed = parsePutty(text, passphrase);
      return PrivateKey.fromComponents(parsed.components, parsed.comment);
    }
    case 'pem':
      return PrivateKey.fromKeyObject(parsePemPrivate(text, passphrase));
    case 'pkcs8':
    case 'pkcs1':
    case 'sec1':
      return PrivateKey.fromKeyObject(parsePemPrivate(text, passphrase, effective));
    default:
      throw new KeyParseError(`Unknown private key format: ${String(effective)}`);
  }
}

/**
 * Parses a public key. With `format: 'auto'` (the default) the format is
 * detected from the content. Private keys are rejected; use
 * {@link parsePrivateKey} and `toPublic()` for those.
 */
export function parsePublicKey(
  input: KeyInput,
  options: Omit<ParseOptions<PublicKeyFormat>, 'passphrase'> = {},
): PublicKey {
  const format = options.format ?? 'auto';
  const source = normalize(input);

  switch (source.kind) {
    case 'keyObject':
      if (source.keyObject.type !== 'public') throw new TypeError('Expected a public KeyObject');
      return PublicKey.fromKeyObject(source.keyObject);
    case 'jwk':
      if (jwkIsPrivate(source.jwk)) throw new KeyParseError('Expected a public key but got a private JWK');
      return publicFromJwk(source.jwk);
    case 'binary': {
      if (format === 'rfc4716') throw new KeyParseError('The rfc4716 format is text, but binary data was given');
      if (format === 'openssh' || (format === 'auto' && source.data[0] === 0x00)) {
        return PublicKey.fromComponents(decodePublicBlob(source.data));
      }
      return PublicKey.fromKeyObject(parseDerPublic(source.data, format === 'auto' ? undefined : format));
    }
    case 'text':
      return parsePublicText(source.text, format);
  }
}

function parsePublicText(text: string, format: PublicKeyFormat | 'auto'): PublicKey {
  let effective = format;
  if (effective === 'auto') {
    const label = findPemLabel(text);
    if (detectPrivateFormat(text)) {
      throw new KeyParseError('Expected a public key but got a private key; use parsePrivateKey()');
    }
    if (isRfc4716(text)) effective = 'rfc4716';
    else if (label === undefined) effective = 'openssh';
    else if (PUBLIC_PEM_LABELS.includes(label)) effective = label === 'PUBLIC KEY' ? 'spki' : 'pkcs1';
    else throw new KeyParseError(`Unsupported PEM block: ${label}`);
  }
  switch (effective) {
    case 'openssh': {
      const parsed = parseOpenSshPublic(text);
      return PublicKey.fromComponents(parsed.components, parsed.comment);
    }
    case 'rfc4716': {
      const parsed = parseRfc4716(text);
      return PublicKey.fromComponents(parsed.components, parsed.comment);
    }
    case 'spki':
    case 'pkcs1':
      return PublicKey.fromKeyObject(parsePemPublic(text, effective));
    default:
      throw new KeyParseError(`Unknown public key format: ${String(effective)}`);
  }
}

/** Parses either kind of key, detecting the format from the content. */
export function parseKey(input: KeyInput, options: { passphrase?: Passphrase } = {}): PublicKey | PrivateKey {
  const source = normalize(input);
  switch (source.kind) {
    case 'keyObject':
      keyTypeOf(source.keyObject);
      return source.keyObject.type === 'private'
        ? PrivateKey.fromKeyObject(source.keyObject)
        : PublicKey.fromKeyObject(source.keyObject);
    case 'jwk':
      return jwkIsPrivate(source.jwk) ? privateFromJwk(source.jwk) : publicFromJwk(source.jwk);
    case 'text':
      return detectPrivateFormat(source.text)
        ? parsePrivateKey(source.text, options)
        : parsePublicKey(source.text);
    case 'binary':
      if (source.data[0] === 0x00) return parsePublicKey(source.data);
      try {
        return parsePrivateKey(source.data, options);
      } catch (privateError) {
        if (!(privateError instanceof KeyParseError)) throw privateError;
        try {
          return parsePublicKey(source.data);
        } catch (publicError) {
          if (!(publicError instanceof KeyParseError)) throw publicError;
          throw new KeyParseError('Could not detect the key format', { cause: publicError });
        }
      }
  }
}
