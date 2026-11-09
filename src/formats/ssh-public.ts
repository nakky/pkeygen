// SSH public key blobs (RFC 4253 section 6.6, RFC 5656, RFC 8709) and the
// one-line OpenSSH public key format built on top of them.
import { KeyParseError, UnsupportedError } from '../errors';
import { isEcdsaCurve, type PublicComponents } from '../internal/components';
import { SshReader, SshWriter } from '../internal/ssh-buffer';

export function sshTypeOf(c: { type: string; curve?: string }): string {
  switch (c.type) {
    case 'rsa':
      return 'ssh-rsa';
    case 'ecdsa':
      return `ecdsa-sha2-${c.curve}`;
    case 'ed25519':
      return 'ssh-ed25519';
    default:
      throw new UnsupportedError(`Unsupported key type: ${c.type}`);
  }
}

const SSH_TYPE_RE = /^(ssh-rsa|ssh-ed25519|ecdsa-sha2-nistp(256|384|521))$/;

export function isKnownSshType(name: string): boolean {
  return SSH_TYPE_RE.test(name);
}

export function encodePublicBlob(c: PublicComponents): Buffer {
  const w = new SshWriter().writeString(sshTypeOf(c));
  switch (c.type) {
    case 'rsa':
      w.writeMpint(c.e).writeMpint(c.n);
      break;
    case 'ecdsa':
      w.writeString(c.curve).writeString(c.q);
      break;
    case 'ed25519':
      w.writeString(c.publicKey);
      break;
  }
  return w.toBuffer();
}

/** Reads the type specific part of a public key, after the type name. */
export function readPublicFields(sshType: string, r: SshReader): PublicComponents {
  if (sshType === 'ssh-rsa') {
    const e = r.readMpint();
    const n = r.readMpint();
    return { type: 'rsa', n, e };
  }
  if (sshType === 'ssh-ed25519') {
    return { type: 'ed25519', publicKey: Buffer.from(r.readString()) };
  }
  if (sshType.startsWith('ecdsa-sha2-')) {
    const curve = r.readText();
    if (!isEcdsaCurve(curve)) throw new UnsupportedError(`Unsupported elliptic curve: ${curve}`);
    if (sshType !== `ecdsa-sha2-${curve}`) throw new KeyParseError('ECDSA curve does not match the key type');
    return { type: 'ecdsa', curve, q: Buffer.from(r.readString()) };
  }
  if (sshType.includes('-cert-v0')) {
    throw new UnsupportedError('OpenSSH certificates are not supported');
  }
  throw new UnsupportedError(`Unsupported key type: ${sshType}`);
}

export function decodePublicBlob(blob: Buffer): PublicComponents {
  const r = new SshReader(blob);
  const components = readPublicFields(r.readText(), r);
  if (!r.atEnd()) throw new KeyParseError('Unexpected trailing data in public key');
  return components;
}

export interface ParsedPublic {
  components: PublicComponents;
  comment: string;
}

/**
 * Parses a line of an `id_xxx.pub` / `authorized_keys` file. Options placed
 * before the key type (authorized_keys) are skipped.
 */
export function parseOpenSshPublic(text: string): ParsedPublic {
  const line = text
    .split(/\r?\n/)
    .map((l) => l.trim())
    .find((l) => l !== '' && !l.startsWith('#'));
  if (!line) throw new KeyParseError('No key found');

  const tokenRe = /\S+/g;
  for (let m = tokenRe.exec(line); m; m = tokenRe.exec(line)) {
    if (!isKnownSshType(m[0]) && !m[0].includes('-cert-v0')) continue;
    const rest = line.slice(m.index + m[0].length).trimStart();
    const base64 = /^[A-Za-z0-9+/]+={0,2}/.exec(rest)?.[0];
    if (!base64) continue;
    const blob = Buffer.from(base64, 'base64');
    const r = new SshReader(blob);
    if (r.remaining < 4 || r.readText() !== m[0]) continue;
    return { components: decodePublicBlob(blob), comment: rest.slice(base64.length).trim() };
  }
  throw new KeyParseError('Not an OpenSSH public key');
}

export function formatOpenSshPublic(c: PublicComponents, comment: string): string {
  const line = `${sshTypeOf(c)} ${encodePublicBlob(c).toString('base64')}`;
  const cleaned = comment.replace(/[\r\n]+/g, ' ').trim();
  return cleaned ? `${line} ${cleaned}` : line;
}
