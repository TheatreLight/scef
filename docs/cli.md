# CLI Reference

Binary: `scef` (built from `src/main.cpp`)

## Global Usage

```
scef <command> [options]
```

Password is always read from **stdin** (first line, up to newline or EOF). Use pipe or interactive input in production.

```
echo "mypassword" | scef create -c /path/to/dir -f file.txt -s 10485760
```

## Commands

### `create`

Create a new container and encrypt files into it.

```
scef create -c <container_dir> -f <file> [-f <file> ...] -s <size_bytes>
            [--name <filename>]
            [--max_table_size <bytes>]
            [--kdf-profile <name> | --kdf-m <MiB> --kdf-t <n> --kdf-p <n>]
```

**Required arguments:**

| Flag | Type | Description |
|------|------|-------------|
| `-c <dir>` | path | Directory where the container will be created |
| `-f <file>` | path | File to include; repeatable for multiple files |
| `-s <bytes>` | uint64 | Total container size in bytes |

**Optional arguments:**

| Flag | Default | Description |
|------|---------|-------------|
| `--name <filename>` | auto-numbered | Container filename. Default: `container.scef` if absent, otherwise `container_1.scef`, `container_2.scef`, … (auto-numbered to avoid collisions). Filename must not contain `/` or `\`. |
| `--max_table_size <bytes>` | 65536 | Reserved bytes per slot for the encrypted file table |
| `--kdf-profile <name>` | `default` | Use a predefined KDF profile: `fast`, `default`, `high`, `browser` |
| `--kdf-m <MiB>` | — | Manual Argon2id memory in MiB (1–4096; below 8 prints a warning) |
| `--kdf-t <n>` | — | Manual Argon2id iterations (1–100) |
| `--kdf-p <n>` | — | Manual Argon2id parallelism (1–64) |

`--kdf-profile` and `--kdf-m/t/p` are mutually exclusive. Manual KDF parameters are individually optional; unspecified ones fall back to the `default` profile values.

**Sequence:**
1. Reads password from stdin.
2. Validates file sizes against container capacity.
3. Creates and pre-allocates `container.scef`.
4. Generates random 256-bit salt, derives KEK via Argon2id.
5. Generates random 256-bit DEK, wraps it with KEK.
6. Computes header HMAC.
7. Writes initial empty slots at all 4 positions.
8. Encrypts and writes all files as data blocks.
9. Updates file table at all 4 slots.

**Example:**

```sh
echo "s3cr3t" | scef create -c /mnt/usb -f report.pdf -f data.zip -s 104857600 --kdf-profile high
```

### `add`

Add one or more files to an existing container.

```
scef add -c <container_dir> [--name <filename>] -f <file> [-f <file> ...]
```

| Flag | Description |
|------|-------------|
| `-c <dir>` | Container directory |
| `--name <filename>` | Container filename. Default: `container.scef`. If that file is absent and exactly one `*.scef` file exists in the directory, it is used as a fallback. Otherwise the command fails. |
| `-f <file>` | File to add (repeatable) |

**Sequence:**
1. Opens the existing container (reads metadata, verifies HMAC, unwraps DEK).
2. Appends new data blocks starting at `next_write_offset` from the file table.
3. Updates the file table and header version at all 4 slots.

**Example:**

```sh
echo "s3cr3t" | scef add -c /mnt/usb -f newfile.docx
```

### `list`

List files stored in a container.

```
scef list -c <container_dir> [--name <filename>]
```

| Flag | Description |
|------|-------------|
| `-c <dir>` | Container directory |
| `--name <filename>` | Container filename. Default: `container.scef`. If that file is absent and exactly one `*.scef` file exists in the directory, it is used as a fallback. Otherwise the command fails. |

Prints a text table with filename and size. No `-f` flag needed — always lists all files.

**Example:**

```sh
echo "s3cr3t" | scef list -c /mnt/usb
```

**Output format:**

```
=== SCEF File Table ===
file_count: 2
--- File [0] ---
  name:            report.pdf
  size:            1048576
--- File [1] ---
  name:            data.zip
  size:            524288
```

### `extract`

Decrypt and extract files from a container.

```
scef extract -c <container_dir> -o <output_dir> [--name <filename>] [-f <file> ...]
```

| Flag | Description |
|------|-------------|
| `-c <dir>` | Container directory |
| `-o <dir>` | Output directory for extracted files |
| `--name <filename>` | Container filename. Default: `container.scef`. If that file is absent and exactly one `*.scef` file exists in the directory, it is used as a fallback. Otherwise the command fails. |
| `-f <file>` | Specific file name to extract (optional, repeatable); omit to extract all |

Path traversal protection: file names from the container are sanitized with `std::filesystem::path::filename()`. Names that resolve to `.` or `..` throw an error.

After extraction, SHA-256 checksums are verified against the values in the file table.

**Example — extract all:**

```sh
echo "s3cr3t" | scef extract -c /mnt/usb -o /tmp/output
```

**Example — extract specific file:**

```sh
echo "s3cr3t" | scef extract -c /mnt/usb -o /tmp/output -f report.pdf
```

### `benchmark`

Measure Argon2id timing for all KDF profiles on the current machine.

```
scef benchmark
```

Does not require a password or a container. Takes no arguments. Runs all 4 built-in profiles once each and prints elapsed seconds.

**Example output:**

```
Profile          m (MiB)   t   p    Time
------------------------------------------
browser               64   1   1    0.1s
fast                 256   1   4    0.3s
default             1024   1   4    0.9s
high                2048   1   4    1.7s
```

---

## Global Flags

| Flag | Description |
|------|-------------|
| `--help`, `-h` | Show help and exit |
| `--version` | Print version string and exit |
| `--log-level <level>` | Set minimum log level: `debug`, `info`, `bench`, `warning`, `error`. Default: `info` (Release) or `debug` (Debug build). |
| `-y`, `--yes` | Assume yes for all confirmation prompts (e.g., weak password warning). |
| `--strength-only` | Read password from stdin, print score/bits, exit without performing any container operation. Can be combined with `--kdf-profile` to check against a specific profile's threshold. |
| `--password <string>` | **Scripting/testing only.** Pass the password directly on the command line. **The password is visible in process listings and shell history.** Do not use in production; prefer stdin. |

### `--strength-only` mode

`--strength-only` can appear anywhere in the argument list. When present, the binary reads the password from stdin and prints a one-line result:

```
score=3 bits=41.2
```

`score` is 0–4 (0 = very weak, 4 = very strong). `bits` is `log2(guesses)`. Exit code is always 0 on success.

Combined with `--kdf-profile` to check against a specific profile's strength threshold:

```sh
echo "mypassword" | scef --strength-only --kdf-profile high
```

### Cipher Selection (`--cipher`)

Available at create time only:

| Value | Cipher |
|-------|--------|
| `aes`, `aes-256-gcm` | AES-256-GCM (default) |
| `kuznechik`, `kuznyechik`, `gost` | Kuznechik-GCM (native CLI and GUI only) |

```sh
echo "s3cr3t" | scef create -c /mnt/usb -f file.bin -s 104857600 --cipher kuznechik
```

---

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` (`EXIT_SUCCESS`) | Command completed successfully |
| `1` (`EXIT_FAILURE`) | Error: wrong password, corrupt container, missing arguments, I/O failure, capacity exceeded, etc. |

Error details are always printed to **stderr** (via `LOG_ERROR`).

---

## Container Size Constraints

| Constraint | Value |
|-----------|-------|
| Minimum size | `4 * (4096 + max_table_size)` bytes; default = 278,528 B (~272 KiB) |
| Maximum size | 2 TiB (2^41 bytes) |

If `create` is called with files whose encrypted footprint exceeds the available data capacity, the command fails before creating the container file.

---

## Password Handling

- Read from stdin via `std::getline(std::cin, pw)`.
- Empty password is rejected immediately.
- After Argon2id KDF runs, the password string is zeroed with `Botan::secure_scrub_memory`.

Source: `src/main.cpp:68-75`, `src/FileManager.cpp:187-233`

---

## Logging

The CLI enables console mirroring:

- `INFO` / `DEBUG` messages → stdout
- `WARNING` / `ERROR` messages → stderr

Log files are written to `./logs/` relative to the working directory (rotating, max 1 MiB per file, max 10 files).

In `Release` builds (`NDEBUG`), minimum log level is `INFO`. In `Debug` builds, minimum level is `DEBUG`.
