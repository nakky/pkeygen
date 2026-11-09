import { execFileSync } from 'node:child_process';
import { chmodSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import { generatePrivateKey, generatePrivateKeyAsync, parsePrivateKey, UnsupportedError } from '../src';
import { fixture } from './helpers';

describe('generatePrivateKey', () => {
  it('generates every key type', async () => {
    expect(generatePrivateKey({ type: 'ed25519', comment: 'me' })).toMatchObject({
      type: 'ed25519',
      size: 256,
      comment: 'me',
    });
    expect(generatePrivateKey({ type: 'rsa', bits: 2048 })).toMatchObject({ type: 'rsa', size: 2048 });
    expect(generatePrivateKey({ type: 'ecdsa' })).toMatchObject({ type: 'ecdsa', curve: 'nistp256' });
    expect(generatePrivateKey({ type: 'ecdsa', curve: 'nistp521' }).size).toBe(521);
    expect((await generatePrivateKeyAsync({ type: 'ed25519' })).type).toBe('ed25519');
  });

  it('rejects bad options', async () => {
    expect(() => generatePrivateKey({ type: 'rsa', bits: 512 })).toThrow(RangeError);
    expect(() => generatePrivateKey({ type: 'ecdsa', curve: 'secp256k1' as never })).toThrow(UnsupportedError);
    expect(() => generatePrivateKey({ type: 'dsa' as never })).toThrow(UnsupportedError);
    await expect(generatePrivateKeyAsync({ type: 'rsa', bits: 512 })).rejects.toThrow(RangeError);
  });
});

let sshKeygen = true;
try {
  execFileSync('ssh-keygen', ['-l', '-f', new URL('./fixtures/openssh/ed25519.pub', import.meta.url).pathname]);
} catch {
  sshKeygen = false;
}

describe.skipIf(!sshKeygen)('interoperability with ssh-keygen', () => {
  const dir = mkdtempSync(join(tmpdir(), 'pkeygen-'));
  afterAll(() => rmSync(dir, { recursive: true, force: true }));

  function publicKeyBySshKeygen(name: string, content: string, passphrase = ''): string {
    const file = join(dir, name);
    writeFileSync(file, content);
    chmodSync(file, 0o600);
    return execFileSync('ssh-keygen', ['-y', '-P', passphrase, '-f', file], { encoding: 'utf8' }).trim();
  }

  const keys = [
    () => generatePrivateKey({ type: 'ed25519', comment: 'interop' }),
    () => generatePrivateKey({ type: 'rsa', bits: 2048, comment: 'interop' }),
    () => generatePrivateKey({ type: 'ecdsa', curve: 'nistp256', comment: 'interop' }),
    () => generatePrivateKey({ type: 'ecdsa', curve: 'nistp384', comment: 'interop' }),
    () => generatePrivateKey({ type: 'ecdsa', curve: 'nistp521', comment: 'interop' }),
    () => parsePrivateKey(fixture('putty/ed25519.ppk'), { passphrase: 'foobar' }),
  ];

  it('reads our OpenSSH private keys', () => {
    keys.forEach((make, i) => {
      const key = make();
      const expected = key.toPublic().toString();
      expect(publicKeyBySshKeygen(`plain${i}`, key.toString('openssh'))).toBe(expected);
      expect(publicKeyBySshKeygen(`enc${i}`, key.toString('openssh', { passphrase: 'p w' }), 'p w')).toBe(expected);
      expect(
        publicKeyBySshKeygen(`3des${i}`, key.toString('openssh', { passphrase: 'pw', cipher: '3des-cbc' }), 'pw'),
      ).toBe(expected);
      expect(
        publicKeyBySshKeygen(
          `gcm${i}`,
          key.toString('openssh', { passphrase: 'パス', cipher: 'aes256-gcm@openssh.com', rounds: 3 }),
          'パス',
        ),
      ).toBe(expected);
    });
  });

  it('reads our PEM private keys', () => {
    const rsa = generatePrivateKey({ type: 'rsa', bits: 2048 });
    const expected = rsa.toPublic().toString();
    expect(publicKeyBySshKeygen('pkcs1', rsa.toString('pkcs1'))).toBe(expected);
    expect(publicKeyBySshKeygen('pkcs8', rsa.toString('pkcs8'))).toBe(expected);
    expect(publicKeyBySshKeygen('pkcs8enc', rsa.toString('pkcs8', { passphrase: 'pw' }), 'pw')).toBe(expected);
    const ecdsa = generatePrivateKey({ type: 'ecdsa' });
    expect(publicKeyBySshKeygen('sec1', ecdsa.toString('sec1'))).toBe(ecdsa.toPublic().toString());
  });

  it('reads our public key files', () => {
    const key = generatePrivateKey({ type: 'ed25519' }).toPublic();
    for (const [format, flag] of [
      ['rfc4716', 'RFC4716'],
      ['spki', 'PKCS8'],
    ] as const) {
      const rsa = generatePrivateKey({ type: 'rsa', bits: 2048 }).toPublic();
      const target = format === 'spki' ? rsa : key;
      const file = join(dir, `pub-${format}`);
      writeFileSync(file, target.toString(format));
      const out = execFileSync('ssh-keygen', ['-i', '-m', flag, '-f', file], { encoding: 'utf8' }).trim();
      expect(out).toBe(target.toString('openssh', { comment: '' }));
    }
  });
});
