# CLI Reference

Binary: `scef` (built from `src/main.cpp`)

## Global Usage

```
scef <command> [options]
```

Password is always read from **stdin** (first line, up to newline or EOF). The binary does not provide a `--password` flag — pass the password via pipe or interactive input.

```
echo "mypassword" | scef create -c /path/to/dir -f file.txt -s 10485760
```

## Commands

### `create`

Create a new container and encrypt files into it.

```
scef create -c <container_dir> -f <file> [-f <file> ...] -s <size_bytes>
            [--max_table_size <bytes>]
            [--kdf-profile <name> | --kdf-m <MiB> --kdf-t <n> --kdf-p <n>]
```

**Required arguments:**

| Flag | Type | Description |
|------|------|-------------|
| `-c <dir>` | path | Directory where `container.scef` will be created |
| `-f <file>` | path | File to include; repeatable for multiple files |
| `-s <bytes>` | uint64 | Total container size in bytes |

**Optional arguments:**

| Flag | Default | Description |
|------|---------|-------------|
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
scef add -c <container_dir> -f <file> [-f <file> ...]
```

| Flag | Description |
|------|-------------|
| `-c <dir>` | Container directory containing `container.scef` |
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
scef list -c <container_dir>
```

| Flag | Description |
|------|-------------|
| `-c <dir>` | Container directory |

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
scef extract -c <container_dir> -o <output_dir> [-f <file> ...]
```

| Flag | Description |
|------|-------------|
| `-c <dir>` | Container directory |
| `-o <dir>` | Output directory for extracted files |
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
scef benchmark [--kdf-m <MiB>] [--kdf-t <n>] [--kdf-p <n>] [--csv] [--runs <n>]
```

Does not require a password or a container.

| Flag | Default | Description |
|------|---------|-------------|
| `--kdf-m <MiB>` | — | Add a custom memory config |
| `--kdf-t <n>` | 1 | Custom iterations |
| `--kdf-p <n>` | 4 | Custom parallelism |
| `--csv` | — | Output in CSV format |
| `--runs <n>` | 3 | Runs per config (median reported) |

**Example output:**

```
Profile          m (MiB)   t   p    Time
------------------------------------------
fast                  19   2   1    0.3s
default               64   3   4    1.1s
high                 256   5   8    6.2s
browser               46   1   1    0.8s
```

---

## Global Flags

| Flag | Description |
|------|-------------|
| `--help`, `-h` | Show help and exit |
| `--version` | Print version string and exit |

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
