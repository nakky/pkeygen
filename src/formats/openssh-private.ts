// The "openssh-key-v1" private key format (OpenSSH PROTOCOL.key).
import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';
import { InvalidPassphraseError, KeyEncryptedError, KeyParseError, UnsupportedError } from '../errors';
import { bcryptPbkdf } from '../internal/bcrypt-pbkdf';
import { computeIqmp, toPublicComponents, type PrivateComponents } from '../internal/components';
import { passphraseBytes } from '../internal/passphrase';
import { formatPem, parsePem } from '../internal/pem';
import { SshReader, SshWriter } from '../internal/ssh-buffer';
import type { OpenSshCipher, Passphrase } from '../types';
import { encodePublicBlob, readPublicFields, sshTypeOf } from './ssh-public';

export const OPENSSH_PEM_LABEL = 'OPENSSH PRIVATE KEY';
const MAGIC = Buffer.from('openssh-key-v1\0', 'latin1');
const DEFAULT_CIPHER: OpenSshCipher = 'aes256-ctr';
const DEFAULT_ROUNDS = 16;
const SALT_LENGTH = 16;
const MAX_ROUNDS = 1_000_000;

interface CipherInfo {
  algorithm: string;
  keyLength: number;
  ivLength: number;
  blockSize: number;
  tagLength: number;
}

const cipherInfo = (
  algorithm: string,
  keyLength: number,
  ivLength = 16,
  tagLength = 0,
  blockSize = 16,
): CipherInfo => ({ algorithm, keyLength, ivLength, blockSize, tagLength });

const CIPHERS: Record<string, CipherInfo> = {
  'aes128-ctr': cipherInfo('aes-128-ctr', 16),
  'aes192-ctr': cipherInfo('aes-192-ctr', 24),
  'aes256-ctr': cipherInfo('aes-256-ctr', 32),
  'aes128-cbc': cipherInfo('aes-128-cbc', 16),
  'aes192-cbc': cipherInfo('aes-192-cbc', 24),
  'aes256-cbc': cipherInfo('aes-256-cbc', 32),
  'aes128-gcm@openssh.com': cipherInfo('aes-128-gcm', 16, 12, 16),
  'aes256-gcm@openssh.com': cipherInfo('aes-256-gcm', 32, 12, 16),
  '3des-cbc': cipherInfo('des-ede3-cbc', 24, 8, 0, 8),
};

function lookupCipher(name: string): CipherInfo {
  const info = Object.prototype.hasOwnProperty.call(CIPHERS, name) ? CIPHERS[name] : undefined;
  if (!info) throw new UnsupportedError(`Unsupported OpenSSH private key cipher: ${name}`);
  return info;
}

export interface ParsedPrivate {
  components: PrivateComponents;
  comment: string;
}

function readPrivateFields(r: SshReader): PrivateComponents {
  const sshType = r.readText();
  if (sshType === 'ssh-rsa') {
    const n = r.readMpint();
    const e = r.readMpint();
    const d = r.readMpint();
    const iqmp = r.readMpint();
    const p = r.readMpint();
    const q = r.readMpint();
    return { type: 'rsa', n, e, d, p, q, iqmp };
  }
  const pub = readPublicFields(sshType, r);
  if (pub.type === 'ecdsa') return { ...pub, d: r.readMpint() };
  if (pub.type === 'ed25519') {
    const secret = r.readString();
    if (secret.length !== 64 || !secret.subarray(32).equals(pub.publicKey)) {
      throw new KeyParseError('Invalid Ed25519 private key');
    }
    return { ...pub, seed: Buffer.from(secret.subarray(0, 32)) };
  }
  throw new UnsupportedError(`Unsupported key type: ${sshType}`);
}

export function parseOpenSshPrivate(text: string, passphrase?: Passphrase): ParsedPrivate {
  const pem = parsePem(text);
  if (pem.label !== OPENSSH_PEM_LABEL) throw new KeyParseError('Not an OpenSSH private key');
  const r = new SshReader(pem.body);
  if (r.remaining < MAGIC.length || !r.readBytes(MAGIC.length).equals(MAGIC)) {
    throw new KeyParseError('Not an OpenSSH private key (bad magic)');
  }

  const cipherName = r.readText();
  const kdfName = r.readText();
  const kdfOptions = r.readString();
  const keyCount = r.readUInt32();
  if (keyCount !== 1) throw new UnsupportedError('Only OpenSSH private key files with a single key are supported');
  const publicBlob = r.readString();
  const encrypted = r.readString();

  let section: Buffer;
  const isEncrypted = cipherName !== 'none';
  if (!isEncrypted) {
    if (kdfName !== 'none') throw new KeyParseError('Unencrypted key must not name a KDF');
    section = encrypted;
  } else {
    const cipher = lookupCipher(cipherName);
    if (kdfName !== 'bcrypt') throw new UnsupportedError(`Unsupported OpenSSH private key KDF: ${kdfName}`);
    if (passphrase === undefined || passphrase.length === 0) throw new KeyEncryptedError();
    if (encrypted.length === 0 || encrypted.length % cipher.blockSize !== 0) {
      throw new KeyParseError('Invalid encrypted data length');
    }

    const kdf = new SshReader(kdfOptions);
    const salt = kdf.readString();
    const rounds = kdf.readUInt32();
    if (salt.length === 0 || rounds < 1 || rounds > MAX_ROUNDS) {
      throw new KeyParseError('Invalid KDF options');
    }

    const material = bcryptPbkdf(passphraseBytes(passphrase), salt, cipher.keyLength + cipher.ivLength, rounds);
    const key = material.subarray(0, cipher.keyLength);
    const iv = material.subarray(cipher.keyLength);
    try {
      if (cipher.tagLength > 0) {
        const decipher = createDecipheriv(cipher.algorithm as 'aes-256-gcm', key, iv);
        decipher.setAuthTag(r.readBytes(cipher.tagLength));
        section = Buffer.concat([decipher.update(encrypted), decipher.final()]);
      } else {
        const decipher = createDecipheriv(cipher.algorithm, key, iv).setAutoPadding(false);
        section = Buffer.concat([decipher.update(encrypted), decipher.final()]);
      }
    } catch (cause) {
      if (cause instanceof KeyParseError) throw cause;
      throw new InvalidPassphraseError(undefined, { cause });
    }
  }

  const s = new SshReader(section);
  if (s.remaining < 8 || s.readUInt32() !== s.readUInt32()) {
    if (isEncrypted) throw new InvalidPassphraseError();
    throw new KeyParseError('Corrupted OpenSSH private key (check bytes do not match)');
  }

  const components = readPrivateFields(s);
  const comment = s.readText();
  const padding = s.readRest();
  for (let i = 0; i < padding.length; i++) {
    if (padding[i] !== ((i + 1) & 0xff)) throw new KeyParseError('Corrupted OpenSSH private key (bad padding)');
  }
  if (!encodePublicBlob(toPublicComponents(components)).equals(publicBlob)) {
    throw new KeyParseError('Public and private parts of the key do not match');
  }
  return { components, comment };
}

export interface OpenSshPrivateOptions {
  comment: string;
  passphrase?: Passphrase;
  cipher?: OpenSshCipher;
  rounds?: number;
}

export function formatOpenSshPrivate(c: PrivateComponents, options: OpenSshPrivateOptions): string {
  const encrypt = options.passphrase !== undefined && options.passphrase.length > 0;
  if (options.passphrase !== undefined && !encrypt) throw new RangeError('passphrase must not be empty');
  const cipherName = encrypt ? (options.cipher ?? DEFAULT_CIPHER) : 'none';
  const cipher = encrypt ? lookupCipher(cipherName) : undefined;
  const rounds = options.rounds ?? DEFAULT_ROUNDS;
  if (!Number.isInteger(rounds) || rounds < 1 || rounds > MAX_ROUNDS) {
    throw new RangeError('rounds must be a positive integer');
  }

  const check = randomBytes(4);
  const s = new SshWriter().writeBytes(check).writeBytes(check).writeString(sshTypeOf(c));
  switch (c.type) {
    case 'rsa':
      s.writeMpint(c.n)
        .writeMpint(c.e)
        .writeMpint(c.d)
        .writeMpint(c.iqmp.length > 0 ? c.iqmp : computeIqmp(c.p, c.q))
        .writeMpint(c.p)
        .writeMpint(c.q);
      break;
    case 'ecdsa':
      s.writeString(c.curve).writeString(c.q).writeMpint(c.d);
      break;
    case 'ed25519':
      s.writeString(c.publicKey).writeString(Buffer.concat([c.seed, c.publicKey]));
      break;
  }
  s.writeString(options.comment);

  const blockSize = cipher?.blockSize ?? 8;
  let section = s.toBuffer();
  const padLength = (blockSize - (section.length % blockSize)) % blockSize;
  section = Buffer.concat([section, Buffer.from(Array.from({ length: padLength }, (_, i) => i + 1))]);

  let kdfOptions: Buffer = Buffer.alloc(0);
  let tag: Buffer = Buffer.alloc(0);
  if (cipher) {
    const salt = randomBytes(SALT_LENGTH);
    kdfOptions = new SshWriter().writeString(salt).writeUInt32(rounds).toBuffer();
    const material = bcryptPbkdf(
      passphraseBytes(options.passphrase as Passphrase),
      salt,
      cipher.keyLength + cipher.ivLength,
      rounds,
    );
    const key = material.subarray(0, cipher.keyLength);
    const iv = material.subarray(cipher.keyLength);
    if (cipher.tagLength > 0) {
      const gcm = createCipheriv(cipher.algorithm as 'aes-256-gcm', key, iv);
      section = Buffer.concat([gcm.update(section), gcm.final()]);
      tag = gcm.getAuthTag();
    } else {
      const plain = createCipheriv(cipher.algorithm, key, iv).setAutoPadding(false);
      section = Buffer.concat([plain.update(section), plain.final()]);
    }
  }

  const body = new SshWriter()
    .writeBytes(MAGIC)
    .writeString(cipherName)
    .writeString(encrypt ? 'bcrypt' : 'none')
    .writeString(kdfOptions)
    .writeUInt32(1)
    .writeString(encodePublicBlob(toPublicComponents(c)))
    .writeString(section)
    .writeBytes(tag)
    .toBuffer();
  return formatPem(OPENSSH_PEM_LABEL, body, 70);
}
