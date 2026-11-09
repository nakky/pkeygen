import { createPublicKey, generateKeyPairSync } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { KeyParseError, parseKey, parsePublicKey, PublicKey, UnsupportedError } from '../src';
import { fixture } from './helpers';

const KEYS = [
  { name: 'ed25519', type: 'ed25519', size: 256, sshType: 'ssh-ed25519', comment: 'ed25519 plain' },
  { name: 'rsa', type: 'rsa', size: 2048, sshType: 'ssh-rsa', comment: 'rsa@example' },
  { name: 'ecdsa256', type: 'ecdsa', size: 256, sshType: 'ecdsa-sha2-nistp256', comment: 'ecdsa256' },
  { name: 'ecdsa384_cbc', type: 'ecdsa', size: 384, sshType: 'ecdsa-sha2-nistp384', comment: 'ecdsa384' },
  { name: 'ecdsa521_enc', type: 'ecdsa', size: 521, sshType: 'ecdsa-sha2-nistp521', comment: 'ecdsa521' },
] as const;

// From `ssh-keygen -l` and `ssh-keygen -l -E md5`.
const FINGERPRINTS: Record<string, [string, string]> = {
  ed25519: ['SHA256:y4hmmeBeLWWgzfxLIA64JiOdtzdvsqxi1MkUp4PdtDI', 'MD5:18:91:59:51:46:d8:94:14:8f:78:df:8e:63:d0:57:f9'],
  rsa: ['SHA256:Eset723hmrdNtIohnO+5HIBS0Jyj3Ag4BIKrCq4ONac', 'MD5:3e:f3:b5:5d:1e:38:4c:81:74:06:7b:8a:d3:73:88:2a'],
  ecdsa256: ['SHA256:zWiSnbdwCtutt9J2rxtET9iE0flgA1HtRs5QXz40/pI', 'MD5:42:7e:b3:f6:f8:bc:90:31:09:5d:7c:2f:d8:18:70:a5'],
};

describe('OpenSSH public keys', () => {
  for (const key of KEYS) {
    it(`parses and re-serializes ${key.name}`, () => {
      const text = fixture(`openssh/${key.name}.pub`);
      const parsed = parsePublicKey(text);
      expect(parsed).toBeInstanceOf(PublicKey);
      expect(parsed.type).toBe(key.type);
      expect(parsed.size).toBe(key.size);
      expect(parsed.sshType).toBe(key.sshType);
      expect(parsed.comment).toBe(key.comment);
      expect(parsed.toString('openssh')).toBe(text.trim());
      expect(parsePublicKey(parsed.toBlob()).equals(parsed)).toBe(true);
    });
  }

  it('matches ssh-keygen fingerprints', () => {
    for (const [name, [sha256, md5]] of Object.entries(FINGERPRINTS)) {
      const key = parsePublicKey(fixture(`openssh/${name}.pub`));
      expect(key.fingerprint()).toBe(sha256);
      expect(key.fingerprint('md5')).toBe(md5);
    }
  });

  it('skips authorized_keys options and comments', () => {
    const line = fixture('openssh/ed25519.pub').trim();
    const key = parsePublicKey(`# my keys\n\ncommand="echo ssh-rsa hi",no-pty ${line}\n`);
    expect(key.toString()).toBe(line);
  });

  it('overrides and sanitizes comments', () => {
    const key = parsePublicKey(fixture('openssh/ed25519.pub'));
    expect(key.toString('openssh', { comment: 'a\nb' }).endsWith(' a b')).toBe(true);
    key.comment = '';
    expect(key.toString().split(' ')).toHaveLength(2);
  });

  it('rejects garbage, truncated keys and certificates', () => {
    expect(() => parsePublicKey('hello world')).toThrow(KeyParseError);
    expect(() => parsePublicKey('')).toThrow(KeyParseError);
    const [type, base64] = fixture('openssh/rsa.pub').split(' ') as [string, string];
    expect(() => parsePublicKey(`${type} ${base64.slice(0, 80)}`)).toThrow(KeyParseError);
    // An Ed25519 blob with a point of the wrong length
    const bad = Buffer.concat([
      Buffer.from('0000000b7373682d65643235353139', 'hex'),
      Buffer.from('00000004deadbeef', 'hex'),
    ]);
    expect(() => parsePublicKey(`ssh-ed25519 ${bad.toString('base64')}`)).toThrow(KeyParseError);
  });

  it('rejects ECDSA points that are not on the curve', () => {
    const key = parsePublicKey(fixture('openssh/ecdsa256.pub'));
    const blob = Buffer.from(key.toBlob());
    blob[blob.length - 1]! ^= 0xff;
    expect(() => parsePublicKey(blob)).toThrow(KeyParseError);
  });
});

describe('public key conversions', () => {
  for (const name of ['ed25519', 'rsa', 'ecdsa256']) {
    it(`converts ${name} to and from RFC 4716`, () => {
      const expected = fixture(`openssh/${name}.rfc4716`);
      const key = parsePublicKey(fixture(`openssh/${name}.pub`));
      // ssh-keygen writes its own comment, so compare the keys and our own round trip
      const fromSshKeygen = parsePublicKey(expected);
      expect(fromSshKeygen.equals(key)).toBe(true);
      expect(fromSshKeygen.comment).toMatch(/^\d+-bit /);
      const ours = key.toString('rfc4716');
      expect(ours.split('\n').every((line) => line.length <= 72)).toBe(true);
      const back = parsePublicKey(ours);
      expect(back.equals(key)).toBe(true);
      expect(back.comment).toBe(key.comment);
    });
  }

  it('wraps long RFC 4716 comments', () => {
    const key = parsePublicKey(fixture('openssh/ed25519.pub'));
    const comment = 'long comment '.repeat(12).trim();
    const text = key.toString('rfc4716', { comment });
    expect(text.split('\n').every((line) => Buffer.byteLength(line) <= 72)).toBe(true);
    expect(parsePublicKey(text).comment).toBe(comment);
  });

  it('matches ssh-keygen SPKI and PKCS#1 output', () => {
    const rsa = parsePublicKey(fixture('openssh/rsa.pub'));
    expect(rsa.toString('spki')).toBe(fixture('openssh/rsa.spki.pem'));
    expect(rsa.toString('pkcs1')).toBe(fixture('openssh/rsa.pkcs1.pub.pem'));
    expect(parsePublicKey(fixture('openssh/rsa.spki.pem')).equals(rsa)).toBe(true);
    expect(parsePublicKey(fixture('openssh/rsa.pkcs1.pub.pem')).equals(rsa)).toBe(true);
    expect(parsePublicKey(rsa.toDer('spki')).equals(rsa)).toBe(true);
    expect(parsePublicKey(rsa.toDer('pkcs1')).equals(rsa)).toBe(true);

    const ecdsa = parsePublicKey(fixture('openssh/ecdsa256.pub'));
    expect(parsePublicKey(fixture('openssh/ecdsa256.spki.pem')).equals(ecdsa)).toBe(true);
    expect(parsePublicKey(ecdsa.toString('spki')).equals(ecdsa)).toBe(true);
  });

  it('only allows pkcs1 for RSA', () => {
    const key = parsePublicKey(fixture('openssh/ed25519.pub'));
    expect(() => key.toString('pkcs1')).toThrow(UnsupportedError);
  });

  it('round trips JWK and KeyObject', () => {
    for (const { name } of KEYS) {
      const key = parsePublicKey(fixture(`openssh/${name}.pub`));
      expect(parsePublicKey(key.toJwk()).equals(key)).toBe(true);
      expect(parsePublicKey(JSON.stringify(key.toJwk())).equals(key)).toBe(true);
      expect(parsePublicKey(key.toKeyObject()).equals(key)).toBe(true);
      expect(parseKey(key.toJwk())).toBeInstanceOf(PublicKey);
    }
  });

  it('honours an explicit format', () => {
    const text = fixture('openssh/rsa.spki.pem');
    expect(parsePublicKey(text, { format: 'spki' }).type).toBe('rsa');
    expect(() => parsePublicKey(text, { format: 'pkcs1' })).toThrow(KeyParseError);
    expect(() => parsePublicKey(text, { format: 'openssh' })).toThrow(KeyParseError);
  });

  it('rejects private keys and unsupported key types', () => {
    expect(() => parsePublicKey(fixture('openssh/ed25519'))).toThrow(/private key/);
    const { publicKey } = generateKeyPairSync('x25519');
    expect(() => parsePublicKey(publicKey)).toThrow(UnsupportedError);
    const k1 = generateKeyPairSync('ec', { namedCurve: 'secp256k1' });
    expect(() => parsePublicKey(k1.publicKey.export({ type: 'spki', format: 'pem' }))).toThrow(UnsupportedError);
    expect(createPublicKey(fixture('openssh/rsa.spki.pem')).type).toBe('public');
  });

  it('does not leak anything unexpected through JSON', () => {
    const key = parsePublicKey(fixture('openssh/ed25519.pub'));
    expect(JSON.parse(JSON.stringify(key))).toEqual({
      type: 'ed25519',
      size: 256,
      fingerprint: key.fingerprint(),
      comment: 'ed25519 plain',
    });
  });
});
