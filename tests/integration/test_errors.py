"""
test_errors.py — Tests for error paths, boundary conditions, and CLI flags.

Categories
----------
1. Wrong password: authentication must be enforced; container must survive
   a wrong-password attempt.  Per-command wrong-password exit codes are
   in test_list.py and test_extract.py; 'add' wrong-password and the
   garbage/survival tests live here because they have no better home.
2. Unknown command: unrecognized subcommand must fail and print usage/error.
3. Corrupt containers: truncated, wrong magic, wrong version, garbage bytes.
4. Container size boundaries: sizes below the structural minimum are rejected.
5. --help and --version: must exit 0 and print expected text.
6. Edge-case passwords: single-char, numeric, special characters.
"""

import pathlib
import pytest

from conftest import (
    DEFAULT_PASSWORD,
    create_container,
    list_container,
    extract_files,
    make_text_file,
    make_file_with_bytes,
    run_scef,
    SCEF_BIN,
)

import subprocess

HEADER_SIZE = 4096


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def scef_raw(args: list, stdin_text: str = "\n", timeout: int = 30) -> subprocess.CompletedProcess:
    """
    Run the scef binary without any automatic assertion on exit code.
    stdin_text is passed verbatim (unlike run_scef which appends a password).
    """
    result = subprocess.run(
        [str(SCEF_BIN)] + [str(a) for a in args],
        input=stdin_text,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    return result


def make_valid_container(tmp_path: pathlib.Path) -> pathlib.Path:
    """Create a minimal valid container and return its directory."""
    cdir = tmp_path / "c"
    cdir.mkdir()
    src = make_text_file(tmp_path / "seed.txt", "seed content")
    create_container(cdir, [src], password=DEFAULT_PASSWORD)
    return cdir


# ---------------------------------------------------------------------------
# 1. Wrong password — add command and authentication guarantees
#
# Per-command wrong-password exit codes (list, extract) are tested in
# test_list.py::TestListErrorPaths and test_extract.py::TestExtractErrorPaths.
# Tests here cover the 'add' command (no better home) and the two behavioral
# guarantees that span commands: no garbage plaintext, and container survival.
# ---------------------------------------------------------------------------

class TestWrongPassword:

    def test_add_wrong_password(self, tmp_path):
        """scef add with wrong password must exit non-zero."""
        cdir = make_valid_container(tmp_path)
        new_file = make_text_file(tmp_path / "new.txt", "new content")

        result = run_scef(
            ["add", "-c", str(cdir), "-f", str(new_file)],
            password="wrong_pw",
            expect_success=False,
        )

        assert result.returncode != 0, (
            "scef add with wrong password must exit non-zero"
        )

    def test_wrong_password_does_not_extract_garbage(self, tmp_path):
        """
        AES-GCM authentication must be enforced: extracting with a wrong password
        must exit non-zero AND must not write any plaintext to disk.

        Security properties tested (both unconditional):
          1. returncode != 0  — the operation must be rejected.
          2. output file either does not exist or has size 0  — no plaintext written.

        The previous implementation used an if/else branch that allowed the test
        to pass trivially when the correct implementation wrote no file:
        the else-branch only asserted returncode != 0, which was already guaranteed
        by expect_success=False (not actually an assertion).  This version makes
        both properties unconditional so the test fails if either is violated.
        """
        cdir = tmp_path / "c"
        cdir.mkdir()
        outdir = tmp_path / "out"
        outdir.mkdir()
        expected = b"sensitive data " + bytes(range(100))
        src = make_file_with_bytes(tmp_path / "sensitive.bin", expected)
        create_container(cdir, [src], password="good_password")

        result = run_scef(
            ["extract", "-c", str(cdir), "-o", str(outdir), "-f", "sensitive.bin"],
            password="bad_password",
            expect_success=False,
        )

        # Property 1: wrong password must always produce a non-zero exit code.
        assert result.returncode != 0, (
            "extract with wrong password must exit non-zero; "
            "got returncode=0 — authentication was not enforced"
        )

        # Property 2: no plaintext must be written to disk.
        extracted = outdir / "sensitive.bin"
        assert not extracted.exists() or extracted.stat().st_size == 0, (
            "extract with wrong password wrote a non-empty file to disk — "
            "plaintext confidentiality is violated regardless of whether the "
            "content happens to match the original"
        )

    def test_correct_password_after_wrong_attempt(self, tmp_path):
        """
        A failed wrong-password extract attempt must not corrupt the container.
        The correct password must still work afterwards.
        """
        cdir = tmp_path / "c"
        cdir.mkdir()
        outdir = tmp_path / "out"
        outdir.mkdir()

        expected = b"must survive wrong password attempt"
        src = make_file_with_bytes(tmp_path / "survive.bin", expected)
        create_container(cdir, [src], password="real_password")

        # Attempt with wrong password — should fail.
        run_scef(
            ["extract", "-c", str(cdir), "-o", str(outdir), "-f", "survive.bin"],
            password="wrong_password",
            expect_success=False,
        )

        # Now extract with the correct password — must succeed and be correct.
        extract_files(cdir, outdir, files=["survive.bin"], password="real_password")

        actual = (outdir / "survive.bin").read_bytes()
        assert actual == expected, (
            "Container was corrupted by a wrong-password extract attempt"
        )


# ---------------------------------------------------------------------------
# 2. Unknown command
# ---------------------------------------------------------------------------

class TestUnknownCommand:

    def test_unknown_subcommand_fails(self):
        result = scef_raw(["frobnicate"])
        assert result.returncode != 0, (
            "Unknown subcommand 'frobnicate' must exit non-zero"
        )

    def test_unknown_subcommand_prints_something(self):
        result = scef_raw(["not_a_command"])
        output = result.stdout + result.stderr
        assert len(output.strip()) > 0, (
            "Unknown subcommand should print error or help text"
        )

    def test_misspelled_create_fails(self):
        result = scef_raw(["creat"])
        assert result.returncode != 0, (
            "Misspelled subcommand 'creat' must exit non-zero"
        )


# ---------------------------------------------------------------------------
# 3. Corrupt containers
# ---------------------------------------------------------------------------

class TestCorruptContainers:

    def _write_container(self, cdir: pathlib.Path, data: bytes):
        (cdir / "container.scef").write_bytes(data)

    def test_list_empty_file(self, tmp_path):
        cdir = tmp_path / "c"
        cdir.mkdir()
        self._write_container(cdir, b"")

        result = list_container(cdir, expect_success=False)
        assert result.returncode != 0, (
            "scef list on 0-byte container must fail"
        )

    def test_list_file_smaller_than_header(self, tmp_path):
        cdir = tmp_path / "c"
        cdir.mkdir()
        self._write_container(cdir, b"\x00" * 512)

        result = list_container(cdir, expect_success=False)
        assert result.returncode != 0, (
            "scef list on container smaller than header (512 bytes) must fail"
        )

    def test_list_file_exactly_header_size_wrong_magic(self, tmp_path):
        cdir = tmp_path / "c"
        cdir.mkdir()
        # Header-sized buffer filled with zeros — magic is 0x00000000, not "SCEF"
        self._write_container(cdir, b"\x00" * HEADER_SIZE)

        result = list_container(cdir, expect_success=False)
        assert result.returncode != 0, (
            "scef list on header-sized buffer with wrong magic must fail"
        )

    def test_list_wrong_magic_bytes(self, tmp_path):
        cdir = tmp_path / "c"
        cdir.mkdir()
        bad = b"EVIL" + b"\x00" * (HEADER_SIZE - 4)
        self._write_container(cdir, bad)

        result = list_container(cdir, expect_success=False)
        assert result.returncode != 0, (
            "scef list on container with magic 'EVIL' must fail"
        )

    def test_list_random_garbage(self, tmp_path):
        cdir = tmp_path / "c"
        cdir.mkdir()
        # Deterministic "random" garbage — do not use os.urandom to keep test repeatable
        garbage = bytes((i * 251 + 137) & 0xFF for i in range(HEADER_SIZE * 2))
        self._write_container(cdir, garbage)

        result = list_container(cdir, expect_success=False)
        assert result.returncode != 0, (
            "scef list on garbage-filled file must fail"
        )

    def test_list_truncated_valid_container(self, tmp_path):
        """Truncate a valid container to 1 byte — must fail gracefully."""
        cdir = tmp_path / "c"
        cdir.mkdir()
        src = make_text_file(tmp_path / "f.txt", "content")
        create_container(cdir, [src])

        container_path = cdir / "container.scef"
        # Truncate to 1 byte
        data = container_path.read_bytes()
        container_path.write_bytes(data[:1])

        result = list_container(cdir, expect_success=False)
        assert result.returncode != 0, (
            "scef list on 1-byte truncated container must fail"
        )

    def test_list_container_single_bit_flip_in_header(self, tmp_path):
        """
        Flip one bit in slot 0 header of a valid container.
        Slot 0 HMAC check fails, but backup slots are intact so
        readMeta() falls back to slot 1 and the operation succeeds.
        """
        cdir = tmp_path / "c"
        cdir.mkdir()
        src = make_text_file(tmp_path / "f.txt", "content")
        create_container(cdir, [src])

        container_path = cdir / "container.scef"
        data = bytearray(container_path.read_bytes())
        # Flip a bit at offset 0x10 (inside kdf_m_kib field in header)
        data[0x10] ^= 0x01
        container_path.write_bytes(bytes(data))

        result = list_container(cdir, expect_success=False)
        assert result.returncode == 0, (
            "scef list must recover from single-bit corruption in slot 0 "
            "via fallback to backup slots"
        )


# ---------------------------------------------------------------------------
# 4. Container size boundaries
#
# -s 0 is tested in test_create.py::TestCreateMissingRequiredArguments.
# Tests here cover sizes that pass the zero check but fall below the
# structural minimum — cases not present in test_create.py.
# ---------------------------------------------------------------------------

class TestContainerSizeBoundaries:

    def test_size_one_byte_rejected(self, tmp_path):
        cdir = tmp_path / "c"
        cdir.mkdir()
        src = make_text_file(tmp_path / "f.txt", "x")
        result = run_scef(
            ["create", "-c", str(cdir), "-f", str(src), "-s", "1"],
            expect_success=False,
        )
        assert result.returncode != 0, (
            "scef create with -s 1 (below minimum) must fail"
        )

    def test_size_below_minimum_rejected(self, tmp_path):
        """Below spec minimum: 4 * (4096 + 65536) = 278528 bytes."""
        cdir = tmp_path / "c"
        cdir.mkdir()
        src = make_text_file(tmp_path / "f.txt", "x")
        below_min = 4 * (4096 + 65536) - 1   # 278527 bytes
        result = run_scef(
            ["create", "-c", str(cdir), "-f", str(src), "-s", str(below_min)],
            expect_success=False,
        )
        assert result.returncode != 0, (
            f"scef create with size {below_min} (1 byte below minimum) must fail"
        )


# ---------------------------------------------------------------------------
# 5. --help and --version
# ---------------------------------------------------------------------------

class TestHelpAndVersion:

    def test_help_flag_exits_zero(self):
        result = scef_raw(["--help"])
        assert result.returncode == 0, (
            f"scef --help must exit 0, got {result.returncode}"
        )

    def test_help_short_flag_exits_zero(self):
        result = scef_raw(["-h"])
        assert result.returncode == 0, (
            f"scef -h must exit 0, got {result.returncode}"
        )

    def test_help_output_contains_usage(self):
        result = scef_raw(["--help"])
        output = result.stdout.lower()
        # 'usage' or 'scef' must appear in the help text
        assert "usage" in output or "scef" in output, (
            f"--help output does not contain 'usage' or 'scef':\n{result.stdout}"
        )

    def test_help_output_contains_create(self):
        result = scef_raw(["--help"])
        assert "create" in result.stdout, (
            f"--help output missing 'create' command:\n{result.stdout}"
        )

    def test_help_output_contains_add(self):
        result = scef_raw(["--help"])
        assert "add" in result.stdout, (
            f"--help output missing 'add' command:\n{result.stdout}"
        )

    def test_help_output_contains_list(self):
        result = scef_raw(["--help"])
        assert "list" in result.stdout, (
            f"--help output missing 'list' command:\n{result.stdout}"
        )

    def test_help_output_contains_extract(self):
        result = scef_raw(["--help"])
        assert "extract" in result.stdout, (
            f"--help output missing 'extract' command:\n{result.stdout}"
        )

    def test_version_flag_exits_zero(self):
        result = scef_raw(["--version"])
        assert result.returncode == 0, (
            f"scef --version must exit 0, got {result.returncode}"
        )

    def test_version_output_contains_version_number(self):
        result = scef_raw(["--version"])
        output = result.stdout + result.stderr
        assert "0.1.0" in output, (
            f"--version output must contain '0.1.0':\n{output}"
        )

    def test_version_output_contains_scef(self):
        result = scef_raw(["--version"])
        output = result.stdout + result.stderr
        assert "scef" in output.lower(), (
            f"--version output must contain 'scef':\n{output}"
        )


# ---------------------------------------------------------------------------
# 6. Edge-case passwords
# ---------------------------------------------------------------------------

class TestEdgeCasePasswords:

    def test_minimum_length_password(self, tmp_path):
        """A single-character password must be accepted."""
        cdir = tmp_path / "c"
        cdir.mkdir()
        outdir = tmp_path / "out"
        outdir.mkdir()
        src = make_file_with_bytes(tmp_path / "f.bin", b"data")
        password = "x"

        create_container(cdir, [src], password=password)
        extract_files(cdir, outdir, files=["f.bin"], password=password)

        assert (outdir / "f.bin").read_bytes() == b"data"

    def test_numeric_password(self, tmp_path):
        cdir = tmp_path / "c"
        cdir.mkdir()
        outdir = tmp_path / "out"
        outdir.mkdir()
        src = make_file_with_bytes(tmp_path / "f.bin", b"numeric pw test")
        password = "1234567890"

        create_container(cdir, [src], password=password)
        extract_files(cdir, outdir, files=["f.bin"], password=password)

        assert (outdir / "f.bin").read_bytes() == b"numeric pw test"
