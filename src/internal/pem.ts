import { KeyParseError } from '../errors';

export interface PemBlock {
  label: string;
  headers: Record<string, string>;
  body: Buffer;
}

const PEM_RE = /-----BEGIN ([A-Z0-9 ]+)-----\r?\n([\s\S]*?)-----END \1-----/;

export function findPemLabel(text: string): string | undefined {
  return /-----BEGIN ([A-Z0-9 ]+)-----/.exec(text)?.[1];
}

export function parsePem(text: string): PemBlock {
  const match = PEM_RE.exec(text);
  if (!match) throw new KeyParseError('No PEM block found');
  const label = match[1] as string;
  const lines = (match[2] as string).split(/\r?\n/);

  // RFC 1421 style headers (used by legacy encrypted PEM) end at the first blank line.
  const headers: Record<string, string> = {};
  let start = 0;
  if (lines.some((line) => /^[A-Za-z0-9-]+:/.test(line))) {
    let name: string | undefined;
    for (; start < lines.length; start++) {
      const line = lines[start] as string;
      if (line.trim() === '') {
        start++;
        break;
      }
      const header = /^([A-Za-z0-9-]+):\s*(.*)$/.exec(line);
      if (header) {
        name = (header[1] as string).toLowerCase();
        headers[name] = header[2] as string;
      } else if (name && /^\s/.test(line)) {
        headers[name] += line.trim();
      } else {
        break;
      }
    }
  }

  const base64 = lines.slice(start).join('').replace(/\s+/g, '');
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(base64)) {
    throw new KeyParseError('PEM body is not valid base64');
  }
  return { label, headers, body: Buffer.from(base64, 'base64') };
}

export function wrap(text: string, width: number): string[] {
  const lines: string[] = [];
  for (let i = 0; i < text.length; i += width) lines.push(text.slice(i, i + width));
  return lines;
}

export function formatPem(label: string, body: Buffer, width = 64): string {
  return [`-----BEGIN ${label}-----`, ...wrap(body.toString('base64'), width), `-----END ${label}-----`, ''].join(
    '\n',
  );
}
