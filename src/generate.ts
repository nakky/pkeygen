import { generateKeyPair, generateKeyPairSync, type KeyObject } from 'node:crypto';
import { UnsupportedError } from './errors';
import { CURVES, isEcdsaCurve } from './internal/components';
import { PrivateKey } from './key';
import type { GenerateOptions } from './types';

const DEFAULT_RSA_BITS = 3072;
const MIN_RSA_BITS = 1024;

function rsaBits(bits: number | undefined): number {
  const value = bits ?? DEFAULT_RSA_BITS;
  if (!Number.isInteger(value) || value < MIN_RSA_BITS) {
    throw new RangeError(`RSA keys must have at least ${MIN_RSA_BITS} bits`);
  }
  return value;
}

function namedCurve(curve: string | undefined): string {
  const name = curve ?? 'nistp256';
  if (!isEcdsaCurve(name)) throw new UnsupportedError(`Unsupported elliptic curve: ${name}`);
  return CURVES[name].openssl;
}

/** Generates a new private key. The public key is available through `toPublic()`. */
export function generatePrivateKey(options: GenerateOptions): PrivateKey {
  let privateKey: KeyObject;
  switch (options.type) {
    case 'ed25519':
      ({ privateKey } = generateKeyPairSync('ed25519'));
      break;
    case 'rsa':
      ({ privateKey } = generateKeyPairSync('rsa', { modulusLength: rsaBits(options.bits) }));
      break;
    case 'ecdsa':
      ({ privateKey } = generateKeyPairSync('ec', { namedCurve: namedCurve(options.curve) }));
      break;
    default:
      throw new UnsupportedError(`Unsupported key type: ${String((options as { type: unknown }).type)}`);
  }
  return PrivateKey.fromKeyObject(privateKey, options.comment);
}

/** Like {@link generatePrivateKey}, without blocking the event loop (useful for large RSA keys). */
export function generatePrivateKeyAsync(options: GenerateOptions): Promise<PrivateKey> {
  return new Promise((resolve, reject) => {
    const done = (error: Error | null, _publicKey: KeyObject, privateKey: KeyObject): void => {
      if (error) reject(error);
      else resolve(PrivateKey.fromKeyObject(privateKey, options.comment));
    };
    try {
      switch (options.type) {
        case 'ed25519':
          generateKeyPair('ed25519', {}, done);
          break;
        case 'rsa':
          generateKeyPair('rsa', { modulusLength: rsaBits(options.bits) }, done);
          break;
        case 'ecdsa':
          generateKeyPair('ec', { namedCurve: namedCurve(options.curve) }, done);
          break;
        default:
          throw new UnsupportedError(`Unsupported key type: ${String((options as { type: unknown }).type)}`);
      }
    } catch (error) {
      reject(error);
    }
  });
}
