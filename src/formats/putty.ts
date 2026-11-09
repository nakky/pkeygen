// PuTTY private key files (.ppk), versions 2 and 3.
// https://tartarus.org/~simon/putty-snapshots/htmldoc/AppendixC.html
import { createCipheriv, createDecipheriv, createHash, createHmac, timingSafeEqual } from 'node:crypto';
import { InvalidPassphraseError, KeyEncryptedError, KeyParseError, UnsupportedError } from '../errors';
import { computeIqmp, toPublicComponents, type PrivateComponents } from '../internal/components';
import { passphraseBytes } from '../internal/passphrase';
import { wrap } from '../internal/pem';
import { SshReader, SshWriter, toFixedLength } from '../internal/ssh-buffer';
import type { Passphrase } from '../types';
import type { ParsedPrivate } from './openssh-private';
import { decodePublicBlob, encodePublicBlob, sshTypeOf } from './ssh-public';

const HEADER_RE = /^PuTTY-User-Key-File-(\d+): *(.*)$/;
const CIPHER = 'aes256-cbc';
const BLOCK_SIZE = 16;

export function isPutty(text: string): boolean {
  return /^PuTTY-User-Key-File-\d+:/m.test(text);
}

const sha1 = (...parts: Uint8Array[]): Buffer => {
  const hash = createHash('sha1');
  for (const part of parts) hash.update(part);
  return hash.digest();
};

function deriveV2Key(passphrase: Buffer): Buffer {
  return Buffer.concat([
    sha1(Buffer.from([0, 0, 0, 0]), passphrase),
    sha1(Buffer.from([0, 0, 0, 1]), passphrase),
  ]).subarray(0, 32);
}

function computeMac(
  version: number,
  macPassphrase: Buffer,
  fields: { algorithm: string; encryption: string; comment: string; publicBlob: Buffer; privateBlob: Buffer },
): Buffer {
  const data = new SshWriter()
    .writeString(fields.algorithm)
    .writeString(fields.encryption)
    .writeString(fields.comment)
    .writeString(fields.publicBlob)
    .writeString(fields.privateBlob)
    .toBuffer();
  if (version === 2) {
    const key = sha1(Buffer.from('putty-private-key-file-mac-key', 'ascii'), macPassphrase);
    return createHmac('sha1', key).update(data).digest();
  }
  // Version 3 derives the MAC key with Argon2 for encrypted keys; only
  // unencrypted keys (empty MAC key) are supported here.
  return createHmac('sha256', Buffer.alloc(0)).update(data).digest();
}

class LineReader {
  private index = 0;
  constructor(private readonly lines: string[]) {}

  next(): string {
    const line = this.lines[this.index++];
    if (line === undefined) throw new KeyParseError('Unexpected end of PuTTY key file');
    return line;
  }

  header(name: string): string {
    const line = this.next();
    const colon = line.indexOf(':');
    if (colon === -1 || line.slice(0, colon).toLowerCase() !== name.toLowerCase()) {
      throw new KeyParseError(`Expected "${name}" header in PuTTY key file`);
    }
    return line.slice(colon + 1).replace(/^ /, '');
  }

  base64Block(name: string): Buffer {
    const count = Number(this.header(name));
    if (!Number.isInteger(count) || count < 0 || count > this.lines.length) {
      throw new KeyParseError(`Invalid "${name}" value in PuTTY key file`);
    }
    let base64 = '';
    for (let i = 0; i < count; i++) base64 += this.next().trim();
    if (!/^[A-Za-z0-9+/]*={0,2}$/.test(base64)) throw new KeyParseError('PuTTY key file contains invalid base64');
    return Buffer.from(base64, 'base64');
  }
}

export function parsePutty(text: string, passphrase?: Passphrase): ParsedPrivate {
  const lines = text.split(/\r\n|\r|\n/);
  while (lines.length > 0 && !HEADER_RE.test(lines[0] as string)) lines.shift();
  const reader = new LineReader(lines);
  const first = HEADER_RE.exec(lines.length > 0 ? reader.next() : '');
  if (!first) throw new KeyParseError('Not a PuTTY private key file');

  const version = Number(first[1]);
  const algorithm = (first[2] as string).trim();
  if (version !== 2 && version !== 3) {
    throw new UnsupportedError(`Unsupported PuTTY key file version: ${version}`);
  }

  const encryption = reader.header('Encryption').trim();
  const comment = reader.header('Comment');
  const publicBlob = reader.base64Block('Public-Lines');
  if (encryption !== 'none' && encryption !== CIPHER) {
    throw new UnsupportedError(`Unsupported PuTTY key encryption: ${encryption}`);
  }
  const isEncrypted = encryption !== 'none';
  if (isEncrypted && version === 3) {
    throw new UnsupportedError(
      'Encrypted PuTTY version 3 keys (Argon2) are not supported; re-save the key as PPK version 2 or without a passphrase',
    );
  }
  let privateBlob = reader.base64Block('Private-Lines');
  const mac = Buffer.from(reader.header('Private-MAC').trim(), 'hex');

  const pass = passphraseBytes(passphrase);
  if (isEncrypted) {
    if (pass.length === 0) throw new KeyEncryptedError();
    if (privateBlob.length === 0 || privateBlob.length % BLOCK_SIZE !== 0) {
      throw new KeyParseError('Invalid encrypted data length');
    }
    const decipher = createDecipheriv('aes-256-cbc', deriveV2Key(pass), Buffer.alloc(16)).setAutoPadding(false);
    privateBlob = Buffer.concat([decipher.update(privateBlob), decipher.final()]);
  }

  const expected = computeMac(version, isEncrypted ? pass : Buffer.alloc(0), {
    algorithm,
    encryption,
    comment,
    publicBlob,
    privateBlob,
  });
  if (mac.length !== expected.length || !timingSafeEqual(mac, expected)) {
    if (isEncrypted) throw new InvalidPassphraseError();
    throw new KeyParseError('PuTTY key file is corrupted (MAC mismatch)');
  }

  const pub = decodePublicBlob(publicBlob);
  if (sshTypeOf(pub) !== algorithm) throw new KeyParseError('Key algorithm does not match the public key');

  const r = new SshReader(privateBlob);
  let components: PrivateComponents;
  switch (pub.type) {
    case 'rsa': {
      const d = r.readMpint();
      const p = r.readMpint();
      const q = r.readMpint();
      const iqmp = r.readMpint();
      components = { ...pub, d, p, q, iqmp };
      break;
    }
    case 'ecdsa':
      components = { ...pub, d: r.readMpint() };
      break;
    case 'ed25519':
      components = { ...pub, seed: toFixedLength(r.readString(), 32) };
      break;
  }
  return { components, comment };
}

export interface PuttyOptions {
  comment: string;
  passphrase?: Passphrase;
  version?: 2 | 3;
}

export function formatPutty(c: PrivateComponents, options: PuttyOptions): string {
  const version = options.version ?? 2;
  if (version !== 2 && version !== 3) throw new RangeError('ppkVersion must be 2 or 3');
  const pass = passphraseBytes(options.passphrase);
  if (options.passphrase !== undefined && pass.length === 0) throw new RangeError('passphrase must not be empty');
  const encrypt = pass.length > 0;
  if (encrypt && version === 3) {
    throw new UnsupportedError('Encrypted PuTTY version 3 keys (Argon2) are not supported; use ppkVersion 2');
  }

  const algorithm = sshTypeOf(c);
  const encryption = encrypt ? CIPHER : 'none';
  const comment = options.comment.replace(/[\r\n]+/g, ' ');
  const publicBlob = encodePublicBlob(toPublicComponents(c));

  const w = new SshWriter();
  switch (c.type) {
    case 'rsa':
      w.writeMpint(c.d)
        .writeMpint(c.p)
        .writeMpint(c.q)
        .writeMpint(c.iqmp.length > 0 ? c.iqmp : computeIqmp(c.p, c.q));
      break;
    case 'ecdsa':
      w.writeMpint(c.d);
      break;
    case 'ed25519':
      w.writeString(c.seed);
      break;
  }
  let privateBlob = w.toBuffer();
  if (encrypt) {
    const padLength = (BLOCK_SIZE - (privateBlob.length % BLOCK_SIZE)) % BLOCK_SIZE;
    privateBlob = Buffer.concat([privateBlob, sha1(privateBlob).subarray(0, padLength)]);
  }

  const mac = computeMac(version, pass, { algorithm, encryption, comment, publicBlob, privateBlob });
  let stored = privateBlob;
  if (encrypt) {
    const cipher = createCipheriv('aes-256-cbc', deriveV2Key(pass), Buffer.alloc(16)).setAutoPadding(false);
    stored = Buffer.concat([cipher.update(privateBlob), cipher.final()]);
  }

  const publicLines = wrap(publicBlob.toString('base64'), 64);
  const privateLines = wrap(stored.toString('base64'), 64);
  return [
    `PuTTY-User-Key-File-${version}: ${algorithm}`,
    `Encryption: ${encryption}`,
    `Comment: ${comment}`,
    `Public-Lines: ${publicLines.length}`,
    ...publicLines,
    `Private-Lines: ${privateLines.length}`,
    ...privateLines,
    `Private-MAC: ${mac.toString('hex')}`,
    '',
  ].join('\r\n');
}
