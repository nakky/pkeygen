// Raw key components and their conversion from/to Node.js KeyObjects.
// Integers are unsigned big-endian magnitudes.
import { createECDH, createPrivateKey, createPublicKey, type JsonWebKey, type KeyObject } from 'node:crypto';
import { KeyParseError, UnsupportedError } from '../errors';
import type { EcdsaCurve, KeyType } from '../types';
import { stripLeadingZeros, toFixedLength } from './ssh-buffer';

export type PublicComponents =
  | { type: 'rsa'; n: Buffer; e: Buffer }
  | { type: 'ecdsa'; curve: EcdsaCurve; q: Buffer }
  | { type: 'ed25519'; publicKey: Buffer };

export type PrivateComponents =
  | { type: 'rsa'; n: Buffer; e: Buffer; d: Buffer; p: Buffer; q: Buffer; iqmp: Buffer }
  | { type: 'ecdsa'; curve: EcdsaCurve; q: Buffer; d: Buffer }
  | { type: 'ed25519'; publicKey: Buffer; seed: Buffer };

interface CurveInfo {
  jwk: string;
  openssl: string;
  bits: number;
  bytes: number;
}

export const CURVES: Record<EcdsaCurve, CurveInfo> = {
  nistp256: { jwk: 'P-256', openssl: 'prime256v1', bits: 256, bytes: 32 },
  nistp384: { jwk: 'P-384', openssl: 'secp384r1', bits: 384, bytes: 48 },
  nistp521: { jwk: 'P-521', openssl: 'secp521r1', bits: 521, bytes: 66 },
};

const ED25519_PKCS8_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');

export function isEcdsaCurve(name: string): name is EcdsaCurve {
  return Object.prototype.hasOwnProperty.call(CURVES, name);
}

function curveFromJwk(crv: string | undefined): EcdsaCurve {
  for (const [name, info] of Object.entries(CURVES)) {
    if (info.jwk === crv) return name as EcdsaCurve;
  }
  throw new UnsupportedError(`Unsupported elliptic curve: ${crv ?? 'unknown'}`);
}

const fromB64 = (value: string | undefined, field: string): Buffer => {
  if (typeof value !== 'string') throw new KeyParseError(`Key is missing the "${field}" field`);
  return Buffer.from(value, 'base64url');
};
const toB64 = (value: Buffer): string => value.toString('base64url');

const toBigInt = (value: Buffer): bigint => (value.length === 0 ? 0n : BigInt('0x' + value.toString('hex')));

function fromBigInt(value: bigint): Buffer {
  const hex = value.toString(16);
  return stripLeadingZeros(Buffer.from(hex.length % 2 ? '0' + hex : hex, 'hex'));
}

function modInverse(a: bigint, m: bigint): bigint {
  let [r0, r1] = [((a % m) + m) % m, m];
  let [s0, s1] = [1n, 0n];
  while (r1 !== 0n) {
    const quotient = r0 / r1;
    [r0, r1] = [r1, r0 - quotient * r1];
    [s0, s1] = [s1, s0 - quotient * s1];
  }
  if (r0 !== 1n) throw new KeyParseError('Invalid RSA key: primes are not coprime');
  return ((s0 % m) + m) % m;
}

/** Computes q^-1 mod p. */
export function computeIqmp(p: Buffer, q: Buffer): Buffer {
  return fromBigInt(modInverse(toBigInt(q), toBigInt(p)));
}

export function keyTypeOf(keyObject: KeyObject): KeyType {
  switch (keyObject.asymmetricKeyType) {
    case 'rsa':
      return 'rsa';
    case 'ec':
      return 'ecdsa';
    case 'ed25519':
      return 'ed25519';
    default:
      throw new UnsupportedError(`Unsupported key type: ${keyObject.asymmetricKeyType ?? keyObject.type}`);
  }
}

export function publicComponentsFromJwk(jwk: JsonWebKey): PublicComponents {
  switch (jwk.kty) {
    case 'RSA':
      return {
        type: 'rsa',
        n: stripLeadingZeros(fromB64(jwk.n, 'n')),
        e: stripLeadingZeros(fromB64(jwk.e, 'e')),
      };
    case 'EC': {
      const curve = curveFromJwk(jwk.crv);
      const size = CURVES[curve].bytes;
      return {
        type: 'ecdsa',
        curve,
        q: Buffer.concat([
          Buffer.from([0x04]),
          toFixedLength(fromB64(jwk.x, 'x'), size),
          toFixedLength(fromB64(jwk.y, 'y'), size),
        ]),
      };
    }
    case 'OKP':
      if (jwk.crv !== 'Ed25519') throw new UnsupportedError(`Unsupported key type: ${jwk.crv}`);
      return { type: 'ed25519', publicKey: fromB64(jwk.x, 'x') };
    default:
      throw new UnsupportedError(`Unsupported key type: ${jwk.kty ?? 'unknown'}`);
  }
}

export function privateComponentsFromJwk(jwk: JsonWebKey): PrivateComponents {
  const pub = publicComponentsFromJwk(jwk);
  switch (pub.type) {
    case 'rsa': {
      const p = stripLeadingZeros(fromB64(jwk.p, 'p'));
      const q = stripLeadingZeros(fromB64(jwk.q, 'q'));
      return { ...pub, d: stripLeadingZeros(fromB64(jwk.d, 'd')), p, q, iqmp: computeIqmp(p, q) };
    }
    case 'ecdsa':
      return { ...pub, d: stripLeadingZeros(fromB64(jwk.d, 'd')) };
    case 'ed25519':
      return { ...pub, seed: fromB64(jwk.d, 'd') };
  }
}

export function publicComponentsOf(keyObject: KeyObject): PublicComponents {
  keyTypeOf(keyObject);
  const publicKey = keyObject.type === 'private' ? createPublicKey(keyObject) : keyObject;
  return publicComponentsFromJwk(publicKey.export({ format: 'jwk' }));
}

export function privateComponentsOf(keyObject: KeyObject): PrivateComponents {
  keyTypeOf(keyObject);
  return privateComponentsFromJwk(keyObject.export({ format: 'jwk' }));
}

export function toPublicComponents(c: PrivateComponents): PublicComponents {
  switch (c.type) {
    case 'rsa':
      return { type: 'rsa', n: c.n, e: c.e };
    case 'ecdsa':
      return { type: 'ecdsa', curve: c.curve, q: c.q };
    case 'ed25519':
      return { type: 'ed25519', publicKey: c.publicKey };
  }
}

function publicJwk(c: PublicComponents): JsonWebKey {
  switch (c.type) {
    case 'rsa':
      if (c.n.length === 0 || c.e.length === 0) throw new KeyParseError('Invalid RSA public key');
      return { kty: 'RSA', n: toB64(c.n), e: toB64(c.e) };
    case 'ecdsa': {
      const size = CURVES[c.curve].bytes;
      if (c.q.length !== 1 + 2 * size || c.q[0] !== 0x04) {
        throw new KeyParseError('Invalid ECDSA public key: expected an uncompressed point');
      }
      return {
        kty: 'EC',
        crv: CURVES[c.curve].jwk,
        x: toB64(c.q.subarray(1, 1 + size)),
        y: toB64(c.q.subarray(1 + size)),
      };
    }
    case 'ed25519':
      if (c.publicKey.length !== 32) throw new KeyParseError('Invalid Ed25519 public key length');
      return { kty: 'OKP', crv: 'Ed25519', x: toB64(c.publicKey) };
  }
}

export function keyObjectFromPublicComponents(c: PublicComponents): KeyObject {
  const jwk = publicJwk(c);
  try {
    return createPublicKey({ key: jwk, format: 'jwk' });
  } catch (cause) {
    throw new KeyParseError('Invalid public key data', { cause });
  }
}

/**
 * Builds a private KeyObject, verifying that the public part really belongs
 * to the private part.
 */
export function keyObjectFromPrivateComponents(c: PrivateComponents): KeyObject {
  try {
    switch (c.type) {
      case 'rsa': {
        const [n, d, p, q] = [toBigInt(c.n), toBigInt(c.d), toBigInt(c.p), toBigInt(c.q)];
        if (p < 2n || q < 2n || p * q !== n) {
          throw new KeyParseError('Invalid RSA private key: modulus does not match the primes');
        }
        return createPrivateKey({
          format: 'jwk',
          key: {
            ...publicJwk(c),
            d: toB64(c.d),
            p: toB64(c.p),
            q: toB64(c.q),
            dp: toB64(fromBigInt(d % (p - 1n))),
            dq: toB64(fromBigInt(d % (q - 1n))),
            qi: toB64(computeIqmp(c.p, c.q)),
          },
        });
      }
      case 'ecdsa': {
        const info = CURVES[c.curve];
        const d = toFixedLength(c.d, info.bytes);
        const ecdh = createECDH(info.openssl);
        ecdh.setPrivateKey(d);
        if (!ecdh.getPublicKey().equals(c.q)) {
          throw new KeyParseError('ECDSA public key does not match the private key');
        }
        return createPrivateKey({ format: 'jwk', key: { ...publicJwk(c), d: toB64(d) } });
      }
      case 'ed25519': {
        if (c.seed.length !== 32) throw new KeyParseError('Invalid Ed25519 private key length');
        const keyObject = createPrivateKey({
          key: Buffer.concat([ED25519_PKCS8_PREFIX, c.seed]),
          format: 'der',
          type: 'pkcs8',
        });
        const derived = publicComponentsOf(keyObject);
        if (derived.type !== 'ed25519' || !derived.publicKey.equals(c.publicKey)) {
          throw new KeyParseError('Ed25519 public key does not match the private key');
        }
        return keyObject;
      }
    }
  } catch (cause) {
    if (cause instanceof KeyParseError) throw cause;
    throw new KeyParseError('Invalid private key data', { cause });
  }
}

export function keySizeOf(c: PublicComponents): number {
  switch (c.type) {
    case 'rsa': {
      const first = c.n[0] ?? 0;
      return c.n.length === 0 ? 0 : (c.n.length - 1) * 8 + (32 - Math.clz32(first));
    }
    case 'ecdsa':
      return CURVES[c.curve].bits;
    case 'ed25519':
      return 256;
  }
}
