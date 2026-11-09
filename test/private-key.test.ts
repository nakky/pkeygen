import { createSign, createVerify, sign, verify } from 'node:crypto';
import { inspect } from 'node:util';
import { describe, expect, it } from 'vitest';
import {
  InvalidPassphraseError,
  KeyEncryptedError,
  KeyParseError,
  parseKey,
  parsePrivateKey,
  parsePublicKey,
  PrivateKey,
  PublicKey,
  UnsupportedError,
  type OpenSshCipher,
  type PrivateKeyFormat,
} from '../src';
import { fixture } from './helpers';

const OPENSSH_KEYS = [
  { name: 'ed25519', passphrase: undefined, comment: 'ed25519 plain' },
  { name: 'ed25519_enc', passphrase: 'secret', comment: 'ed25519 encrypted' },
  { name: 'rsa', passphrase: undefined, comment: 'rsa@example' },
  { name: 'rsa_gcm', passphrase: 'secret', comment: 'rsa gcm' },
  { name: 'ecdsa256', passphrase: undefined, comment: 'ecdsa256' },
  { name: 'ecdsa384_cbc', passphrase: 'secret', comment: 'ecdsa384' },
  { name: 'ecdsa521_enc', passphrase: 'パスフレーズ', comment: 'ecdsa521' },
  { name: 'ed25519_3des', passphrase: 'secret', comment: 'ed25519 3des' },
];

function load(name: string, passphrase?: string): PrivateKey {
  return parsePrivateKey(fixture(`openssh/${name}`), { passphrase });
}

/** Proves that the private key really belongs to the public key. */
function expectWorkingPair(privateKey: PrivateKey): void {
  const data = Buffer.from('pkeygen');
  const algorithm = privateKey.type === 'ed25519' ? null : 'sha256';
  const signature = sign(algorithm, data, privateKey.toKeyObject());
  expect(verify(algorithm, data, privateKey.toPublic().toKeyObject(), signature)).toBe(true);
}

describe('OpenSSH private keys', () => {
  for (const key of OPENSSH_KEYS) {
    it(`parses ${key.name}`, () => {
      const parsed = load(key.name, key.passphrase);
      expect(parsed).toBeInstanceOf(PrivateKey);
      expect(parsed.comment).toBe(key.comment);
      expect(parsed.toPublic().toString()).toBe(fixture(`openssh/${key.name}.pub`).trim());
      expectWorkingPair(parsed);
    });
  }

  it('writes unencrypted keys exactly like ssh-keygen apart from the check bytes', () => {
    for (const name of ['ed25519', 'rsa', 'ecdsa256']) {
      const original = fixture(`openssh/${name}`);
      const ours = load(name).toString('openssh');
      expect(ours.length).toBe(original.length);
      expect(ours.split('\n').slice(0, 2)).toEqual(original.split('\n').slice(0, 2));
      expect(load(name).equals(parsePrivateKey(ours))).toBe(true);
    }
  });

  it('requires a passphrase for encrypted keys', () => {
    expect(() => load('ed25519_enc')).toThrow(KeyEncryptedError);
    expect(() => load('ed25519_enc', '')).toThrow(KeyEncryptedError);
  });

  it('rejects a wrong passphrase', () => {
    expect(() => load('ed25519_enc', 'wrong')).toThrow(InvalidPassphraseError);
    expect(() => load('rsa_gcm', 'wrong')).toThrow(InvalidPassphraseError);
    expect(() => load('ecdsa384_cbc', 'wrong')).toThrow(InvalidPassphraseError);
    expect(() => load('ed25519_3des', 'wrong')).toThrow(InvalidPassphraseError);
  });

  it('ignores a passphrase for unencrypted keys', () => {
    expect(load('ed25519', 'unused').type).toBe('ed25519');
  });

  const ciphers: OpenSshCipher[] = [
    'aes128-ctr',
    'aes192-ctr',
    'aes256-ctr',
    'aes128-cbc',
    'aes192-cbc',
    'aes256-cbc',
    'aes128-gcm@openssh.com',
    'aes256-gcm@openssh.com',
    '3des-cbc',
  ];
  for (const cipher of ciphers) {
    it(`round trips an encrypted key with ${cipher}`, () => {
      const key = load('ed25519');
      const text = key.toString('openssh', { passphrase: 'pw', cipher, rounds: 2, comment: 'new comment' });
      expect(() => parsePrivateKey(text)).toThrow(KeyEncryptedError);
      expect(() => parsePrivateKey(text, { passphrase: 'pW' })).toThrow(InvalidPassphraseError);
      const back = parsePrivateKey(text, { passphrase: Buffer.from('pw') });
      expect(back.equals(key)).toBe(true);
      expect(back.comment).toBe('new comment');
    });
  }

  it('detects tampering', () => {
    const lines = fixture('openssh/ed25519').trim().split('\n');
    const body = Buffer.from(lines.slice(1, -1).join(''), 'base64');
    const rebuild = (data: Buffer): string =>
      [lines[0], data.toString('base64'), lines[lines.length - 1], ''].join('\n');

    const checkBytes = Buffer.from(body);
    const offset = body.indexOf(Buffer.from('ssh-ed25519'), 60) - 12;
    checkBytes[offset]! ^= 1;
    expect(() => parsePrivateKey(rebuild(checkBytes))).toThrow(KeyParseError);

    // Swap in another key's public part
    const other = parsePublicKey(fixture('openssh/ed25519_enc.pub')).toBlob();
    const mismatched = Buffer.from(body);
    other.copy(mismatched, body.indexOf(Buffer.from('ssh-ed25519')) - 4);
    expect(() => parsePrivateKey(rebuild(mismatched))).toThrow(/do not match/);

    expect(() => parsePrivateKey(rebuild(body.subarray(0, 100)))).toThrow(KeyParseError);
  });
});

describe('PEM private keys', () => {
  it('parses ssh-keygen PEM output', () => {
    const rsa = load('rsa');
    expect(parsePrivateKey(fixture('openssh/rsa.pkcs1.pem')).equals(rsa)).toBe(true);
    expect(parsePrivateKey(fixture('openssh/rsa.pkcs1_enc.pem'), { passphrase: 'secret' }).equals(rsa)).toBe(true);
    const ecdsa = load('ecdsa256');
    expect(parsePrivateKey(fixture('openssh/ecdsa256.sec1.pem')).equals(ecdsa)).toBe(true);
    expect(
      parsePrivateKey(fixture('openssh/ecdsa256.pkcs8_enc.pem'), { passphrase: 'secret' }).equals(ecdsa),
    ).toBe(true);
  });

  it('reports missing and wrong passphrases', () => {
    for (const name of ['rsa.pkcs1_enc.pem', 'ecdsa256.pkcs8_enc.pem']) {
      expect(() => parsePrivateKey(fixture(`openssh/${name}`))).toThrow(KeyEncryptedError);
      expect(() => parsePrivateKey(fixture(`openssh/${name}`), { passphrase: 'wrong' })).toThrow(
        InvalidPassphraseError,
      );
    }
  });

  it('matches ssh-keygen PKCS#1 output byte for byte', () => {
    expect(load('rsa').toString('pkcs1')).toBe(fixture('openssh/rsa.pkcs1.pem'));
  });

  const cases: Array<[string, PrivateKeyFormat[]]> = [
    ['rsa', ['pkcs8', 'pkcs1']],
    ['ecdsa256', ['pkcs8', 'sec1']],
    ['ecdsa384_cbc', ['pkcs8', 'sec1']],
    ['ecdsa521_enc', ['pkcs8', 'sec1']],
    ['ed25519', ['pkcs8']],
  ];
  for (const [name, formats] of cases) {
    for (const format of formats) {
      it(`round trips ${name} through ${format}`, () => {
        const passphrase = OPENSSH_KEYS.find((k) => k.name === name)?.passphrase;
        const key = load(name, passphrase);
        const plain = key.toString(format);
        expect(parsePrivateKey(plain).equals(key)).toBe(true);
        expect(parsePrivateKey(plain, { format }).equals(key)).toBe(true);

        const encrypted = key.toString(format, { passphrase: 'pw' });
        expect(encrypted).not.toBe(plain);
        expect(() => parsePrivateKey(encrypted)).toThrow(KeyEncryptedError);
        expect(parsePrivateKey(encrypted, { passphrase: 'pw' }).equals(key)).toBe(true);

        if (format !== 'putty' && format !== 'openssh') {
          expect(parsePrivateKey(key.toDer(format)).equals(key)).toBe(true);
        }
        expectWorkingPair(parsePrivateKey(plain));
      });
    }
  }

  it('rejects formats that do not fit the key type', () => {
    expect(() => load('ed25519').toString('pkcs1')).toThrow(UnsupportedError);
    expect(() => load('ed25519').toString('sec1')).toThrow(UnsupportedError);
    expect(() => load('rsa').toString('sec1')).toThrow(UnsupportedError);
    expect(() => load('ecdsa256').toString('pkcs1')).toThrow(UnsupportedError);
    expect(() => parsePrivateKey(fixture('openssh/rsa.pkcs1.pem'), { format: 'pkcs8' })).toThrow(KeyParseError);
  });
});

describe('PrivateKey', () => {
  it('round trips JWK and KeyObject', () => {
    for (const name of ['ed25519', 'rsa', 'ecdsa256']) {
      const key = load(name);
      const viaJwk = parsePrivateKey(key.toJwk());
      expect(viaJwk.toString('pkcs8')).toBe(key.toString('pkcs8'));
      expect(parsePrivateKey(key.toKeyObject()).equals(key)).toBe(true);
      expect(parseKey(key.toJwk())).toBeInstanceOf(PrivateKey);
      expect(() => parsePublicKey(key.toJwk())).toThrow(KeyParseError);
    }
  });

  it('auto detects with parseKey', () => {
    expect(parseKey(fixture('openssh/ed25519'))).toBeInstanceOf(PrivateKey);
    expect(parseKey(fixture('openssh/ed25519_enc'), { passphrase: 'secret' })).toBeInstanceOf(PrivateKey);
    expect(parseKey(fixture('openssh/rsa.pkcs1.pem'))).toBeInstanceOf(PrivateKey);
    expect(parseKey(fixture('putty/rsa-v3.ppk'))).toBeInstanceOf(PrivateKey);
    expect(parseKey(load('rsa').toDer('pkcs8'))).toBeInstanceOf(PrivateKey);
    expect(parseKey(load('rsa').toDer('pkcs1'))).toBeInstanceOf(PrivateKey);
    expect(parseKey(Buffer.from(fixture('openssh/ed25519')))).toBeInstanceOf(PrivateKey);
    expect(() => parseKey('nonsense')).toThrow(KeyParseError);
    expect(() => parseKey(Buffer.from([0x30, 0x03, 0x02, 0x01, 0x00]))).toThrow(KeyParseError);
    expect(parseKey(load('rsa').toPublic().toDer('spki'))).toBeInstanceOf(PublicKey);
    expect(parseKey(load('rsa').toPublic().toBlob())).toBeInstanceOf(PublicKey);
    const encryptedDer = load('rsa').toDer('pkcs8', { passphrase: 'pw' });
    expect(() => parseKey(encryptedDer)).toThrow(KeyEncryptedError);
    expect(() => parseKey(encryptedDer, { passphrase: 'no' })).toThrow(InvalidPassphraseError);
    expect(parseKey(encryptedDer, { passphrase: 'pw' })).toBeInstanceOf(PrivateKey);
    for (const format of ['pkcs8', 'pkcs1'] as const) {
      expect(() => parsePublicKey(load('rsa').toDer(format))).toThrow(/private key/);
    }
  });

  it('keeps secrets out of JSON and inspect output', () => {
    const key = load('ed25519');
    const seed = key.toJwk().d as string;
    expect(JSON.stringify(key)).not.toContain(seed);
    expect(Object.keys(JSON.parse(JSON.stringify(key)))).toEqual(['type', 'size', 'fingerprint', 'comment']);
    const hex = Buffer.from(seed, 'base64url').toString('hex');
    expect(inspect(key, { depth: 5 })).not.toContain(hex.slice(0, 16));
  });

  it('rejects an empty passphrase when writing', () => {
    for (const format of ['openssh', 'putty', 'pkcs8'] as const) {
      expect(() => load('ed25519').toString(format, { passphrase: '' })).toThrow(RangeError);
    }
  });

  it('signs with RSA after conversion', () => {
    const key = parsePrivateKey(load('rsa').toString('putty'));
    const signature = createSign('sha256').update('x').sign(key.toKeyObject());
    expect(createVerify('sha256').update('x').verify(load('rsa').toPublic().toKeyObject(), signature)).toBe(true);
  });
});
