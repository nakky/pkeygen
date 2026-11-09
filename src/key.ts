import { createHash, createPublicKey, type JsonWebKey, type KeyObject } from 'node:crypto';
import { UnsupportedError } from './errors';
import { formatOpenSshPrivate } from './formats/openssh-private';
import { exportPrivate, exportPublic } from './formats/pem-keys';
import { formatPutty } from './formats/putty';
import { formatRfc4716 } from './formats/rfc4716';
import { encodePublicBlob, formatOpenSshPublic, sshTypeOf } from './formats/ssh-public';
import {
  keyObjectFromPrivateComponents,
  keyObjectFromPublicComponents,
  keySizeOf,
  keyTypeOf,
  privateComponentsOf,
  publicComponentsOf,
  type PrivateComponents,
  type PublicComponents,
} from './internal/components';
import type {
  EcdsaCurve,
  FingerprintAlgorithm,
  KeyType,
  Passphrase,
  PrivateKeyDerFormat,
  PrivateKeyFormat,
  PrivateKeyWriteOptions,
  PublicKeyDerFormat,
  PublicKeyFormat,
  PublicKeyWriteOptions,
} from './types';

function computeFingerprint(blob: Buffer, algorithm: FingerprintAlgorithm): string {
  switch (algorithm) {
    case 'md5':
      return 'MD5:' + (createHash('md5').update(blob).digest('hex').match(/../g) as string[]).join(':');
    case 'sha1':
    case 'sha256':
    case 'sha512':
      return `${algorithm.toUpperCase()}:${createHash(algorithm).update(blob).digest('base64').replace(/=+$/, '')}`;
    default:
      throw new UnsupportedError(`Unsupported fingerprint algorithm: ${String(algorithm)}`);
  }
}

abstract class BaseKey {
  /** Free-form comment, kept by the `openssh`, `rfc4716` and `putty` formats. */
  comment: string;
  readonly type: KeyType;
  /** Only set for ECDSA keys. */
  readonly curve?: EcdsaCurve;
  /** Key size in bits. */
  readonly size: number;

  /** @internal */
  protected readonly publicComponents: PublicComponents;

  protected constructor(publicComponents: PublicComponents, comment: string) {
    this.publicComponents = publicComponents;
    this.comment = comment;
    this.type = publicComponents.type;
    if (publicComponents.type === 'ecdsa') this.curve = publicComponents.curve;
    this.size = keySizeOf(publicComponents);
  }

  /** SSH key type name, e.g. `ssh-ed25519` or `ecdsa-sha2-nistp256`. */
  get sshType(): string {
    return sshTypeOf(this.publicComponents);
  }

  /** Fingerprint of the public key in the style of `ssh-keygen -l`, e.g. `SHA256:...`. */
  fingerprint(algorithm: FingerprintAlgorithm = 'sha256'): string {
    return computeFingerprint(encodePublicBlob(this.publicComponents), algorithm);
  }
}

export class PublicKey extends BaseKey {
  private readonly keyObject: KeyObject;

  private constructor(keyObject: KeyObject, components: PublicComponents, comment: string) {
    super(components, comment);
    this.keyObject = keyObject;
  }

  /** Wraps a Node.js KeyObject. A private KeyObject yields its public key. */
  static fromKeyObject(keyObject: KeyObject, comment = ''): PublicKey {
    keyTypeOf(keyObject);
    const publicKey = keyObject.type === 'private' ? createPublicKey(keyObject) : keyObject;
    return new PublicKey(publicKey, publicComponentsOf(publicKey), comment);
  }

  /** @internal */
  static fromComponents(components: PublicComponents, comment = ''): PublicKey {
    return new PublicKey(keyObjectFromPublicComponents(components), components, comment);
  }

  /** The binary SSH public key blob (RFC 4253), i.e. the base64 part of an OpenSSH public key. */
  toBlob(): Buffer {
    return encodePublicBlob(this.publicComponents);
  }

  override toString(format: PublicKeyFormat = 'openssh', options: PublicKeyWriteOptions = {}): string {
    const comment = options.comment ?? this.comment;
    switch (format) {
      case 'openssh':
        return formatOpenSshPublic(this.publicComponents, comment);
      case 'rfc4716':
        return formatRfc4716(this.publicComponents, comment);
      case 'spki':
      case 'pkcs1':
        return exportPublic(this.keyObject, format, 'pem');
      default:
        throw new UnsupportedError(`Unsupported public key format: ${String(format)}`);
    }
  }

  toDer(format: PublicKeyDerFormat = 'spki'): Buffer {
    return exportPublic(this.keyObject, format, 'der');
  }

  toJwk(): JsonWebKey {
    return this.keyObject.export({ format: 'jwk' });
  }

  toKeyObject(): KeyObject {
    return this.keyObject;
  }

  equals(other: PublicKey | PrivateKey): boolean {
    const blob = other instanceof PrivateKey ? other.toPublic().toBlob() : other.toBlob();
    return this.toBlob().equals(blob);
  }

  toJSON(): { type: KeyType; size: number; fingerprint: string; comment: string } {
    return { type: this.type, size: this.size, fingerprint: this.fingerprint(), comment: this.comment };
  }
}

export class PrivateKey extends BaseKey {
  private readonly keyObject: KeyObject;
  private components: PrivateComponents | undefined;

  private constructor(keyObject: KeyObject, components: PrivateComponents | undefined, comment: string) {
    super(publicComponentsOf(keyObject), comment);
    this.keyObject = keyObject;
    this.components = components;
    // Keep secrets out of console.log / util.inspect output.
    Object.defineProperty(this, 'keyObject', { enumerable: false });
    Object.defineProperty(this, 'components', { enumerable: false });
  }

  static fromKeyObject(keyObject: KeyObject, comment = ''): PrivateKey {
    if (keyObject.type !== 'private') throw new TypeError('Expected a private KeyObject');
    keyTypeOf(keyObject);
    return new PrivateKey(keyObject, undefined, comment);
  }

  /** @internal */
  static fromComponents(components: PrivateComponents, comment = ''): PrivateKey {
    return new PrivateKey(keyObjectFromPrivateComponents(components), components, comment);
  }

  private getComponents(): PrivateComponents {
    return (this.components ??= privateComponentsOf(this.keyObject));
  }

  toPublic(): PublicKey {
    return PublicKey.fromComponents(this.publicComponents, this.comment);
  }

  override toString(format: PrivateKeyFormat = 'openssh', options: PrivateKeyWriteOptions = {}): string {
    const comment = options.comment ?? this.comment;
    const { passphrase } = options;
    switch (format) {
      case 'openssh':
        return formatOpenSshPrivate(this.getComponents(), {
          comment,
          passphrase,
          cipher: options.cipher,
          rounds: options.rounds,
        });
      case 'putty':
        return formatPutty(this.getComponents(), { comment, passphrase, version: options.ppkVersion });
      case 'pkcs8':
      case 'pkcs1':
      case 'sec1':
        return exportPrivate(this.keyObject, format, 'pem', { passphrase, cipher: options.pemCipher });
      default:
        throw new UnsupportedError(`Unsupported private key format: ${String(format)}`);
    }
  }

  toDer(format: PrivateKeyDerFormat = 'pkcs8', options: { passphrase?: Passphrase; pemCipher?: string } = {}): Buffer {
    return exportPrivate(this.keyObject, format, 'der', {
      passphrase: options.passphrase,
      cipher: options.pemCipher,
    });
  }

  /** The JWK includes the private parameters. */
  toJwk(): JsonWebKey {
    return this.keyObject.export({ format: 'jwk' });
  }

  toKeyObject(): KeyObject {
    return this.keyObject;
  }

  equals(other: PublicKey | PrivateKey): boolean {
    return this.toPublic().equals(other);
  }

  /** Never includes private material. */
  toJSON(): { type: KeyType; size: number; fingerprint: string; comment: string } {
    return { type: this.type, size: this.size, fingerprint: this.fingerprint(), comment: this.comment };
  }
}
