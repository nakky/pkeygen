// RFC 4716 "SSH2 PUBLIC KEY" files, which is also PuTTY's public key format.
import { KeyParseError } from '../errors';
import type { PublicComponents } from '../internal/components';
import { wrap } from '../internal/pem';
import { decodePublicBlob, encodePublicBlob, type ParsedPublic } from './ssh-public';

const BEGIN = '---- BEGIN SSH2 PUBLIC KEY ----';
const END = '---- END SSH2 PUBLIC KEY ----';

export function isRfc4716(text: string): boolean {
  return text.includes(BEGIN);
}

export function parseRfc4716(text: string): ParsedPublic {
  const lines = text.split(/\r\n|\r|\n/).map((l) => l.trimEnd());
  const begin = lines.indexOf(BEGIN);
  const end = lines.indexOf(END, begin + 1);
  if (begin === -1 || end === -1) throw new KeyParseError('Not an RFC 4716 public key');

  let comment = '';
  let i = begin + 1;
  while (i < end && /^[^\s:]{1,64}:/.test(lines[i] as string)) {
    let header = lines[i++] as string;
    while (header.endsWith('\\') && i < end) header = header.slice(0, -1) + (lines[i++] as string);
    const colon = header.indexOf(':');
    if (header.slice(0, colon).toLowerCase() === 'comment') {
      comment = header.slice(colon + 1).trim();
      if (comment.length >= 2 && comment.startsWith('"') && comment.endsWith('"')) {
        comment = comment.slice(1, -1);
      }
    }
  }

  const base64 = lines.slice(i, end).join('').replace(/\s+/g, '');
  if (base64 === '' || !/^[A-Za-z0-9+/]+={0,2}$/.test(base64)) {
    throw new KeyParseError('RFC 4716 body is not valid base64');
  }
  return { components: decodePublicBlob(Buffer.from(base64, 'base64')), comment };
}

export function formatRfc4716(c: PublicComponents, comment: string): string {
  const lines = [BEGIN];
  const cleaned = comment.replace(/[\r\n]+/g, ' ').trim();
  if (cleaned) {
    // Lines are limited to 72 bytes; longer headers continue after a backslash.
    let header = `Comment: "${cleaned}"`;
    while (Buffer.byteLength(header) > 72) {
      let cut = 71;
      while (Buffer.byteLength(header.slice(0, cut)) > 71) cut--;
      lines.push(header.slice(0, cut) + '\\');
      header = header.slice(cut);
    }
    lines.push(header);
  }
  lines.push(...wrap(encodePublicBlob(c).toString('base64'), 70), END, '');
  return lines.join('\n');
}
