// bcrypt_pbkdf as used by OpenSSH to protect private keys
// (OpenBSD lib/libutil/bcrypt_pbkdf.c).
import { createHash } from 'node:crypto';
import { INITIAL_P, INITIAL_S } from './blowfish-constants';

const BCRYPT_WORDS = 8;
const BCRYPT_HASHSIZE = BCRYPT_WORDS * 4;
const CIPHERTEXT = Buffer.from('OxychromaticBlowfishSwatDynamite', 'ascii');

class Blowfish {
  readonly p = Uint32Array.from(INITIAL_P);
  readonly s = Uint32Array.from(INITIAL_S);
  private streamOffset = 0;

  private round(x: number): number {
    const s = this.s;
    return (
      (((s[x >>> 24]! + s[0x100 | ((x >>> 16) & 0xff)]!) ^ s[0x200 | ((x >>> 8) & 0xff)]!) +
        s[0x300 | (x & 0xff)]!) |
      0
    );
  }

  encipher(block: Uint32Array, offset: number): void {
    const p = this.p;
    let l = block[offset]! ^ p[0]!;
    let r = block[offset + 1]!;
    for (let i = 1; i <= 16; i += 2) {
      r ^= this.round(l) ^ p[i]!;
      l ^= this.round(r) ^ p[i + 1]!;
    }
    block[offset] = r ^ p[17]!;
    block[offset + 1] = l;
  }

  private streamToWord(data: Uint8Array): number {
    let word = 0;
    for (let i = 0; i < 4; i++) {
      if (this.streamOffset >= data.length) this.streamOffset = 0;
      word = (word << 8) | data[this.streamOffset++]!;
    }
    return word;
  }

  expandState(data: Uint8Array | null, key: Uint8Array): void {
    const { p, s } = this;
    this.streamOffset = 0;
    for (let i = 0; i < p.length; i++) p[i]! ^= this.streamToWord(key);

    this.streamOffset = 0;
    const block = new Uint32Array(2);
    const fill = (target: Uint32Array): void => {
      for (let i = 0; i < target.length; i += 2) {
        if (data) {
          block[0]! ^= this.streamToWord(data);
          block[1]! ^= this.streamToWord(data);
        }
        this.encipher(block, 0);
        target[i] = block[0]!;
        target[i + 1] = block[1]!;
      }
    };
    fill(p);
    fill(s);
  }
}

function bcryptHash(sha2pass: Uint8Array, sha2salt: Uint8Array): Buffer {
  const state = new Blowfish();
  state.expandState(sha2salt, sha2pass);
  for (let i = 0; i < 64; i++) {
    state.expandState(null, sha2salt);
    state.expandState(null, sha2pass);
  }

  const cdata = new Uint32Array(BCRYPT_WORDS);
  for (let i = 0; i < BCRYPT_WORDS; i++) cdata[i] = CIPHERTEXT.readUInt32BE(i * 4);
  for (let i = 0; i < 64; i++) {
    for (let block = 0; block < BCRYPT_WORDS; block += 2) state.encipher(cdata, block);
  }

  const out = Buffer.alloc(BCRYPT_HASHSIZE);
  for (let i = 0; i < BCRYPT_WORDS; i++) out.writeUInt32LE(cdata[i]!, i * 4);
  return out;
}

const sha512 = (...parts: Uint8Array[]): Buffer => {
  const hash = createHash('sha512');
  for (const part of parts) hash.update(part);
  return hash.digest();
};

export function bcryptPbkdf(
  passphrase: Uint8Array,
  salt: Uint8Array,
  keyLength: number,
  rounds: number,
): Buffer {
  if (!Number.isInteger(rounds) || rounds < 1) throw new RangeError('rounds must be a positive integer');
  if (passphrase.length === 0 || salt.length === 0) {
    throw new RangeError('passphrase and salt must not be empty');
  }
  if (!Number.isInteger(keyLength) || keyLength < 1 || keyLength > BCRYPT_HASHSIZE * BCRYPT_HASHSIZE) {
    throw new RangeError('invalid key length');
  }

  const key = Buffer.alloc(keyLength);
  const stride = Math.ceil(keyLength / BCRYPT_HASHSIZE);
  let amount = Math.ceil(keyLength / stride);
  const sha2pass = sha512(passphrase);

  let remaining = keyLength;
  for (let count = 1; remaining > 0; count++) {
    const countBytes = Buffer.alloc(4);
    countBytes.writeUInt32BE(count, 0);

    let tmp = bcryptHash(sha2pass, sha512(salt, countBytes));
    const out = Buffer.from(tmp);
    for (let i = 1; i < rounds; i++) {
      tmp = bcryptHash(sha2pass, sha512(tmp));
      for (let j = 0; j < out.length; j++) out[j]! ^= tmp[j]!;
    }

    amount = Math.min(amount, remaining);
    let i = 0;
    for (; i < amount; i++) {
      const dest = i * stride + (count - 1);
      if (dest >= keyLength) break;
      key[dest] = out[i]!;
    }
    remaining -= i;
  }
  return key;
}
