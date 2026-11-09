/** Base class of every error thrown by this library. */
export class PkeygenError extends Error {
  constructor(message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = new.target.name;
  }
}

/** The input could not be parsed as a key in the requested (or any known) format. */
export class KeyParseError extends PkeygenError {}

/** The key is encrypted and no passphrase was given. */
export class KeyEncryptedError extends PkeygenError {
  constructor(message = 'Key is encrypted; a passphrase is required') {
    super(message);
  }
}

/** The passphrase did not decrypt the key (or the encrypted data is corrupted). */
export class InvalidPassphraseError extends PkeygenError {
  constructor(message = 'Incorrect passphrase or corrupted key', options?: { cause?: unknown }) {
    super(message, options);
  }
}

/** The key type, format, cipher or combination of them is not supported. */
export class UnsupportedError extends PkeygenError {}
