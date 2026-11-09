# Test fixtures

These keys exist only for testing. Never use them for anything else.

- `openssh/`: generated with `ssh-keygen` (OpenSSH 9.9). Encrypted keys use the
  passphrase `secret`, except `ecdsa521_enc`, which uses `パスフレーズ`.
- `putty/`: PuTTY generated keys taken from the test suite of
  [node-sshpk](https://github.com/TritonDataCenter/node-sshpk) (MIT License,
  Copyright Joyent, Inc.). Encrypted keys use the passphrase `foobar`.
