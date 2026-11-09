# pkeygen

Parse, convert and generate SSH keys in TypeScript / JavaScript.

- **Zero dependencies** – built on `node:crypto`
- **TypeScript first** – ships type definitions, ESM and CommonJS builds
- **Formats**: OpenSSH, PEM (PKCS#1 / PKCS#8 / SPKI / SEC1), PuTTY `.ppk`, RFC 4716, JWK, DER
- **Key types**: RSA, ECDSA (nistp256 / nistp384 / nistp521), Ed25519
- Encrypted private keys (passphrases) are supported for reading and writing

## Install

```sh
npm install pkeygen
```

Requires Node.js 18 or later. Browsers are not supported.

## Usage

### Convert a private key

```ts
import { readFileSync } from 'node:fs';
import { parsePrivateKey } from 'pkeygen';

// The format is detected automatically
const key = parsePrivateKey(readFileSync('id_rsa.pem', 'utf8'), { passphrase: 'old passphrase' });

key.toString('openssh');                              // -----BEGIN OPENSSH PRIVATE KEY-----
key.toString('openssh', { passphrase: 'new secret' }); // encrypted (aes256-ctr + bcrypt)
key.toString('pkcs8');                                // -----BEGIN PRIVATE KEY-----
key.toString('pkcs1');                                // -----BEGIN RSA PRIVATE KEY----- (RSA only)
key.toString('sec1');                                 // -----BEGIN EC PRIVATE KEY-----  (ECDSA only)
key.toString('putty');                                // PuTTY-User-Key-File-2: ...

key.toPublic().toString();                            // ssh-rsa AAAA... comment
```

### Convert a public key

```ts
import { parsePublicKey } from 'pkeygen';

const key = parsePublicKey('ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI... me@example.com');

key.type;                  // 'ed25519'
key.size;                  // 256
key.comment;               // 'me@example.com'
key.fingerprint();         // 'SHA256:...'   (same as ssh-keygen -l)
key.fingerprint('md5');    // 'MD5:18:91:...'

key.toString('openssh');   // ssh-ed25519 AAAA... me@example.com
key.toString('rfc4716');   // ---- BEGIN SSH2 PUBLIC KEY ----
key.toString('spki');      // -----BEGIN PUBLIC KEY-----
key.toString('pkcs1');     // -----BEGIN RSA PUBLIC KEY----- (RSA only)
key.toJwk();               // { kty: 'OKP', crv: 'Ed25519', x: '...' }
key.toKeyObject();         // node:crypto KeyObject
```

### Generate a key pair

```ts
import { generatePrivateKey, generatePrivateKeyAsync } from 'pkeygen';

const key = generatePrivateKey({ type: 'ed25519', comment: 'me@example.com' });
const rsa = await generatePrivateKeyAsync({ type: 'rsa', bits: 4096 });
const ec = generatePrivateKey({ type: 'ecdsa', curve: 'nistp384' });

const privateText = key.toString('openssh', { passphrase: 'secret' });
const publicText = key.toPublic().toString();
```

## API

### Parsing

| Function | Returns |
| --- | --- |
| `parsePrivateKey(input, { format?, passphrase? })` | `PrivateKey` |
| `parsePublicKey(input, { format? })` | `PublicKey` |
| `parseKey(input, { passphrase? })` | `PublicKey \| PrivateKey`, whichever the input is |

`input` can be a `string`, a `Buffer` / `Uint8Array` (text, DER or a binary SSH public key blob),
a JWK object or a `KeyObject`. `format` defaults to `'auto'`.

### Formats

| Format | Public | Private | Notes |
| --- | :-: | :-: | --- |
| `openssh` | ✓ | ✓ | `id_xxx.pub` / `authorized_keys` line, `OPENSSH PRIVATE KEY` |
| `rfc4716` | ✓ | | `SSH2 PUBLIC KEY`, also used by PuTTY for public keys |
| `spki` | ✓ | | PEM `PUBLIC KEY` (`ssh-keygen -m PKCS8`) |
| `pkcs8` | | ✓ | PEM `PRIVATE KEY` / `ENCRYPTED PRIVATE KEY` |
| `pkcs1` | ✓ | ✓ | PEM `RSA PUBLIC KEY` / `RSA PRIVATE KEY`, RSA only |
| `sec1` | | ✓ | PEM `EC PRIVATE KEY`, ECDSA only |
| `putty` | | ✓ | `.ppk` version 2 and 3 |

DER output is available through `toDer()`, JWK through `toJwk()`.

### `PublicKey` / `PrivateKey`

| Member | Description |
| --- | --- |
| `type` | `'rsa' \| 'ecdsa' \| 'ed25519'` |
| `curve` | `'nistp256' \| 'nistp384' \| 'nistp521'` for ECDSA keys |
| `size` | Key size in bits |
| `sshType` | e.g. `ssh-ed25519`, `ecdsa-sha2-nistp256` |
| `comment` | Writable; stored by `openssh`, `rfc4716` and `putty` |
| `fingerprint(algorithm = 'sha256')` | `sha256`, `sha512`, `sha1` or `md5` |
| `toString(format = 'openssh', options?)` | Text representation |
| `toDer(format?)` | DER encoded `Buffer` |
| `toJwk()` / `toKeyObject()` | JWK / `node:crypto` `KeyObject` |
| `equals(other)` | Compares the public parts |
| `toBlob()` (`PublicKey`) | Binary SSH public key blob |
| `toPublic()` (`PrivateKey`) | The matching `PublicKey` |

Options of `PrivateKey#toString()`:

| Option | Formats | Description |
| --- | --- | --- |
| `passphrase` | all | Encrypts the output |
| `comment` | `openssh`, `putty` | Overrides `key.comment` |
| `cipher` | `openssh` | Default `aes256-ctr`; AES CTR / CBC / GCM variants, `3des-cbc` |
| `rounds` | `openssh` | bcrypt-pbkdf rounds, default 16 |
| `pemCipher` | `pkcs8`, `pkcs1`, `sec1` | OpenSSL cipher name, default `aes-256-cbc` |
| `ppkVersion` | `putty` | `2` (default) or `3` |

### Errors

All errors extend `PkeygenError`.

| Error | Meaning |
| --- | --- |
| `KeyParseError` | The input is not a valid key |
| `KeyEncryptedError` | The key is encrypted and no passphrase was given |
| `InvalidPassphraseError` | Wrong passphrase (or corrupted encrypted data) |
| `UnsupportedError` | Unsupported key type, cipher or format combination |

```ts
import { KeyEncryptedError, parsePrivateKey } from 'pkeygen';

try {
  parsePrivateKey(text);
} catch (error) {
  if (error instanceof KeyEncryptedError) {
    // ask the user for a passphrase and retry
  }
}
```

## Limitations

- DSA keys, OpenSSH certificates and security keys (`sk-*`) are not supported.
- Encrypted PuTTY **version 3** files use Argon2 and are not supported. Version 2 files
  (with or without a passphrase) and unencrypted version 3 files are.
- OpenSSH private keys encrypted with `chacha20-poly1305@openssh.com` are not supported.
- `3des-cbc` is supported for compatibility only; it is a legacy cipher and should not be chosen for new keys.
- Legacy encrypted PEM (`pkcs1` / `sec1` with a passphrase) uses a weak MD5 based key derivation.
  Prefer `openssh` or `pkcs8` for encrypted output.

## Development

```sh
npm install
npm test          # vitest (uses ssh-keygen for interoperability tests when available)
npm run typecheck
npm run build     # outputs dist/
```

## License

MIT
