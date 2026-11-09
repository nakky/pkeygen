import { KeyParseError } from '../errors';

/** Reader for the SSH wire encoding (RFC 4251 section 5). */
export class SshReader {
  private offset = 0;

  constructor(private readonly buffer: Buffer) {}

  get remaining(): number {
    return this.buffer.length - this.offset;
  }

  atEnd(): boolean {
    return this.remaining === 0;
  }

  readBytes(length: number): Buffer {
    if (length < 0 || length > this.remaining) {
      throw new KeyParseError('Unexpected end of key data');
    }
    const out = this.buffer.subarray(this.offset, this.offset + length);
    this.offset += length;
    return out;
  }

  readUInt32(): number {
    return this.readBytes(4).readUInt32BE(0);
  }

  readString(): Buffer {
    return this.readBytes(this.readUInt32());
  }

  readText(): string {
    return this.readString().toString('utf8');
  }

  /** Reads an mpint and returns its unsigned big-endian magnitude without leading zeros. */
  readMpint(): Buffer {
    const raw = this.readString();
    if (raw.length > 0 && (raw[0] as number) & 0x80) {
      throw new KeyParseError('Negative integers are not valid in keys');
    }
    return stripLeadingZeros(raw);
  }

  readRest(): Buffer {
    return this.readBytes(this.remaining);
  }
}

export class SshWriter {
  private readonly chunks: Buffer[] = [];

  writeBytes(data: Uint8Array): this {
    this.chunks.push(Buffer.from(data));
    return this;
  }

  writeUInt32(value: number): this {
    const b = Buffer.alloc(4);
    b.writeUInt32BE(value, 0);
    this.chunks.push(b);
    return this;
  }

  writeString(data: Uint8Array | string): this {
    const b = typeof data === 'string' ? Buffer.from(data, 'utf8') : Buffer.from(data);
    return this.writeUInt32(b.length).writeBytes(b);
  }

  /** Writes an unsigned big-endian magnitude as an mpint. */
  writeMpint(magnitude: Uint8Array): this {
    const stripped = stripLeadingZeros(Buffer.from(magnitude));
    if (stripped.length > 0 && (stripped[0] as number) & 0x80) {
      return this.writeString(Buffer.concat([Buffer.alloc(1), stripped]));
    }
    return this.writeString(stripped);
  }

  toBuffer(): Buffer {
    return Buffer.concat(this.chunks);
  }
}

export function stripLeadingZeros(data: Buffer): Buffer {
  let i = 0;
  while (i < data.length && data[i] === 0) i++;
  return data.subarray(i);
}

/** Left-pads (or strips leading zeros) so the result is exactly `length` bytes. */
export function toFixedLength(data: Buffer, length: number): Buffer {
  const stripped = stripLeadingZeros(data);
  if (stripped.length > length) {
    throw new KeyParseError('Integer is too large for the key type');
  }
  return Buffer.concat([Buffer.alloc(length - stripped.length), stripped]);
}
