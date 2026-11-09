import { describe, expect, it } from 'vitest';
import { bcryptPbkdf } from '../src/internal/bcrypt-pbkdf';

describe('bcryptPbkdf', () => {
  it('is deterministic and depends on every input', () => {
    const base = bcryptPbkdf(Buffer.from('password'), Buffer.from('salt'), 48, 4);
    expect(base).toHaveLength(48);
    expect(bcryptPbkdf(Buffer.from('password'), Buffer.from('salt'), 48, 4)).toEqual(base);
    expect(bcryptPbkdf(Buffer.from('passwore'), Buffer.from('salt'), 48, 4)).not.toEqual(base);
    expect(bcryptPbkdf(Buffer.from('password'), Buffer.from('salu'), 48, 4)).not.toEqual(base);
    expect(bcryptPbkdf(Buffer.from('password'), Buffer.from('salt'), 48, 5)).not.toEqual(base);
  });

  it('rejects invalid arguments', () => {
    expect(() => bcryptPbkdf(Buffer.alloc(0), Buffer.from('salt'), 32, 1)).toThrow(RangeError);
    expect(() => bcryptPbkdf(Buffer.from('p'), Buffer.alloc(0), 32, 1)).toThrow(RangeError);
    expect(() => bcryptPbkdf(Buffer.from('p'), Buffer.from('s'), 0, 1)).toThrow(RangeError);
    expect(() => bcryptPbkdf(Buffer.from('p'), Buffer.from('s'), 32, 0)).toThrow(RangeError);
  });
});
