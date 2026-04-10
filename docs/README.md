# SCEF Documentation Index

**SCEF — Self-contained Encrypted Container Format**
MEPhI diploma project. Version 0.1.0.

## Document Map

| File | Contents |
|------|----------|
| [architecture.md](architecture.md) | Module map, build targets, dependency graph, project layout |
| [container-format.md](container-format.md) | Binary layout, header fields byte-by-byte, slot system, file table, data blocks |
| [cli.md](cli.md) | CLI commands, arguments, usage examples, exit codes |
| [gui.md](gui.md) | Qt QML GUI: pages, ScefController facade, FileListModel, DriveListModel, user flows |
| [browser-viewer.md](browser-viewer.md) | Browser viewer: JS modules, WebCrypto, hash-wasm Argon2id, file decryption, Streams API |
| [data-flows.md](data-flows.md) | Key derivation, encryption pipeline (add file), decryption pipeline (extract), container creation, header sync |
| [api/scef-lib.md](api/scef-lib.md) | Library public API: all classes, function signatures, parameters, return values |

## Quick Architecture Summary

```
scef_lib  (static, C++20, Qt-free)
  ├── scef              (CLI binary)
  ├── scef_unit_tests   (GTest)
  ├── scef-gui          (Qt 6 QML binary)
  └── generate_vectors  (browser test helper, optional)

browser/              (HTML + JS, no build step)
benchmarks/           (standalone KDF benchmark)
tests/integration/    (Python pytest, drives CLI binary)
```

## Encryption Scheme

```
Password  →  Argon2id(password, salt)  →  KEK  →  AES-256-GCM-decrypt(encrypted_dek)  →  DEK
DEK  →  AES-256-GCM-encrypt(plaintext chunk)  →  [nonce 12B][ciphertext][auth tag 16B]
```

## Container Slot Layout

```
[0%]  SLOT 0: Header(4096 B) + FileTable(max 65536 B)
      DATA BLOCKS ...
[25%] SLOT 1: Header(4096 B) + FileTable(max 65536 B)
      DATA BLOCKS ...
[50%] SLOT 2: Header(4096 B) + FileTable(max 65536 B)
      DATA BLOCKS ...
[75%] SLOT 3: Header(4096 B) + FileTable(max 65536 B)
      DATA BLOCKS ...
```

Minimum container size: 4 x (4096 + 65536) = 278,528 bytes (~272 KiB).
Maximum container size: 2 TiB (2^41 bytes).
