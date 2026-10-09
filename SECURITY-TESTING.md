# Security and regression tests

Production-key tests run against the unmodified SDK and public signed fixtures.
They verify signature validity, rejection of tampering/replay, alternate-origin
rejection, and failure before parsing unsigned success responses. Fixtures contain
no private signing key and cannot satisfy a fresh random nonce.

Protocol regression tests need a server they control. They use a generated test key
only in a test process or temporary source copy. These test-only substitutions are
not build switches in the SDK and are never included in published runtime packages.
They exercise sessions, heartbeat termination, clocks, envelope failures and accounts.

Run from the repository root:
```
npm test
```
