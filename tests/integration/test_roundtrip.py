"""
test_roundtrip.py — End-to-end create → extract → compare tests.

These are the primary regression tests for data integrity. Every scenario
follows the same pattern:

  1. Write known bytes to source files.
  2. Create a container from those files.
  3. Extract from the container into a clean output directory.
  4. Compare the extracted bytes with the originals.

If any bit in the encrypted data or key derivation is wrong, the comparison
will fail. These tests are the strongest indicator that the encryption
pipeline is correct end-to-end.
"""

import pathlib
import os
import pytest

from conftest import (
    DEFAULT_PASSWORD,
    DEFAULT_CONTAINER_SIZE,
    create_container,
    add_file,
    extract_files,
    make_text_file,
    make_binary_file,
    make_file_with_bytes,
)

BLOCK_SIZE = 65536

# Slot-based layout constants (must match Header.h).
HEADER_SIZE = 4096
DEFAULT_MAX_TABLE_SIZE = 65536
# 4 * (header + file-table) = the structural minimum container size.
MINIMAL_CONTAINER_SIZE = 4 * (HEADER_SIZE + DEFAULT_MAX_TABLE_SIZE)  # 278528 bytes


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def assert_files_equal(expected_path: pathlib.Path, actual_path: pathlib.Path):
    """Assert that two files have identical content, with a clear diff message."""
    assert actual_path.exists(), f"Extracted file does not exist: {actual_path}"
    expected = expected_path.read_bytes()
    actual = actual_path.read_bytes()
    assert len(actual) == len(expected), (
        f"{actual_path.name}: size mismatch — "
        f"expected {len(expected)} bytes, got {len(actual)} bytes"
    )
    assert actual == expected, (
        f"{actual_path.name}: byte content mismatch "
        f"(first differing byte at index "
        f"{next(i for i, (a, b) in enumerate(zip(actual, expected)) if a != b)})"
    )


# ---------------------------------------------------------------------------
# Single-file roundtrip
# ---------------------------------------------------------------------------

class TestRoundtripSingleFile:

    def test_text_file_roundtrip(self, tmp_path):
        src = make_text_file(tmp_path / "source.txt", "Hello, roundtrip!\nLine two.\n")
        cdir = tmp_path / "c"
        cdir.mkdir()
        outdir = tmp_path / "out"
        outdir.mkdir()

        create_container(cdir, [src])
        extract_files(cdir, outdir, files=["source.txt"])

        assert_files_equal(src, outdir / "source.txt")

    def test_binary_file_roundtrip(self, tmp_path):
        data = bytes(range(256)) * 8    # 2048 bytes with every possible byte value
        src = make_file_with_bytes(tmp_path / "binary.bin", data)
        cdir = tmp_path / "c"
        cdir.mkdir()
        outdir = tmp_path / "out"
        outdir.mkdir()

        create_container(cdir, [src])
        extract_files(cdir, outdir, files=["binary.bin"])

        assert_files_equal(src, outdir / "binary.bin")

    def test_all_zero_bytes_roundtrip(self, tmp_path):
        src = make_file_with_bytes(tmp_path / "zeros.bin", b"\x00" * 4096)
        cdir = tmp_path / "c"
        cdir.mkdir()
        outdir = tmp_path / "out"
        outdir.mkdir()

        create_container(cdir, [src])
        extract_files(cdir, outdir, files=["zeros.bin"])

        assert_files_equal(src, outdir / "zeros.bin")

    def test_all_ff_bytes_roundtrip(self, tmp_path):
        src = make_file_with_bytes(tmp_path / "ff.bin", b"\xFF" * 4096)
        cdir = tmp_path / "c"
        cdir.mkdir()
        outdir = tmp_path / "out"
        outdir.mkdir()

        create_container(cdir, [src])
        extract_files(cdir, outdir, files=["ff.bin"])

        assert_files_equal(src, outdir / "ff.bin")

    def test_empty_file_roundtrip(self, tmp_path):
        src = make_file_with_bytes(tmp_path / "empty.bin", b"")
        cdir = tmp_path / "c"
        cdir.mkdir()
        outdir = tmp_path / "out"
        outdir.mkdir()

        create_container(cdir, [src])
        extract_files(cdir, outdir, files=["empty.bin"])

        actual = outdir / "empty.bin"
        assert actual.exists(), "Empty file not extracted"
        assert actual.stat().st_size == 0, (
            f"Empty file should have 0 bytes after extract, got {actual.stat().st_size}"
        )

    def test_single_byte_file_roundtrip(self, tmp_path):
        src = make_file_with_bytes(tmp_path / "one.bin", b"\xAB")
        cdir = tmp_path / "c"
        cdir.mkdir()
        outdir = tmp_path / "out"
        outdir.mkdir()

        create_container(cdir, [src])
        extract_files(cdir, outdir, files=["one.bin"])

        assert_files_equal(src, outdir / "one.bin")


# ---------------------------------------------------------------------------
# Multi-file roundtrip
# ---------------------------------------------------------------------------

class TestRoundtripMultipleFiles:

    def test_two_files_roundtrip(self, tmp_path):
        files = {
            "doc.txt":  b"Document content\n",
            "img.bin":  bytes(range(128)),
        }
        srcs = []
        for name, data in files.items():
            srcs.append(make_file_with_bytes(tmp_path / name, data))

        cdir = tmp_path / "c"
        cdir.mkdir()
        outdir = tmp_path / "out"
        outdir.mkdir()

        create_container(cdir, srcs)
        extract_files(cdir, outdir, files=list(files.keys()))

        for name, expected in files.items():
            actual = (outdir / name).read_bytes()
            assert actual == expected, (
                f"Content mismatch for '{name}' in two-file roundtrip"
            )

    def test_five_files_roundtrip(self, tmp_path):
        files = {}
        for i in range(5):
            name = f"file_{i:02d}.bin"
            data = bytes([i] * (128 * (i + 1)))   # varying sizes
            files[name] = data

        srcs = []
        for name, data in files.items():
            srcs.append(make_file_with_bytes(tmp_path / name, data))

        cdir = tmp_path / "c"
        cdir.mkdir()
        outdir = tmp_path / "out"
        outdir.mkdir()

        create_container(cdir, srcs, size=DEFAULT_CONTAINER_SIZE)
        extract_files(cdir, outdir, files=None)

        for name, expected in files.items():
            actual = (outdir / name).read_bytes()
            assert actual == expected, (
                f"Content mismatch for '{name}' in five-file roundtrip"
            )

    def test_mixed_types_roundtrip(self, tmp_path):
        """Text, binary, and zero-filled files in the same container."""
        text_content = "UTF-8 text: hello world\n"
        binary_content = bytes(range(256))
        zeros_content = b"\x00" * 1024

        srcs = [
            make_text_file(tmp_path / "text.txt", text_content),
            make_file_with_bytes(tmp_path / "binary.bin", binary_content),
            make_file_with_bytes(tmp_path / "zeros.bin", zeros_content),
        ]

        cdir = tmp_path / "c"
        cdir.mkdir()
        outdir = tmp_path / "out"
        outdir.mkdir()

        create_container(cdir, srcs)
        extract_files(cdir, outdir, files=None)

        assert (outdir / "text.txt").read_text(encoding="utf-8") == text_content
        assert (outdir / "binary.bin").read_bytes() == binary_content
        assert (outdir / "zeros.bin").read_bytes() == zeros_content


# ---------------------------------------------------------------------------
# Large file roundtrip (multi-block)
# ---------------------------------------------------------------------------

class TestRoundtripLargeFiles:

    def test_exactly_one_block_roundtrip(self, tmp_path):
        expected = bytes(i & 0xFF for i in range(BLOCK_SIZE))
        src = make_file_with_bytes(tmp_path / "oneblock.bin", expected)
        cdir = tmp_path / "c"
        cdir.mkdir()
        outdir = tmp_path / "out"
        outdir.mkdir()
        # BLOCK_SIZE * 4 alone (262144) is below MINIMAL_CONTAINER_SIZE (278528);
        # add slot overhead explicitly so the formula is correct on its own merits.
        size = max(DEFAULT_CONTAINER_SIZE, BLOCK_SIZE * 4 + MINIMAL_CONTAINER_SIZE)

        create_container(cdir, [src], size=size)
        extract_files(cdir, outdir, files=["oneblock.bin"])

        actual = (outdir / "oneblock.bin").read_bytes()
        assert actual == expected, (
            "One-block file content mismatch in roundtrip"
        )

    def test_two_full_blocks_roundtrip(self, tmp_path):
        expected = bytes(i & 0xFF for i in range(BLOCK_SIZE * 2))
        src = make_file_with_bytes(tmp_path / "twoblock.bin", expected)
        cdir = tmp_path / "c"
        cdir.mkdir()
        outdir = tmp_path / "out"
        outdir.mkdir()
        size = max(DEFAULT_CONTAINER_SIZE, BLOCK_SIZE * 8 + MINIMAL_CONTAINER_SIZE)

        create_container(cdir, [src], size=size)
        extract_files(cdir, outdir, files=["twoblock.bin"])

        actual = (outdir / "twoblock.bin").read_bytes()
        assert actual == expected, (
            "Two-block file content mismatch in roundtrip"
        )

    def test_partial_last_block_roundtrip(self, tmp_path):
        """File with 2 full blocks + 1 partial block (63 bytes)."""
        partial_size = BLOCK_SIZE * 2 + 63
        expected = bytes(i & 0xFF for i in range(partial_size))
        src = make_file_with_bytes(tmp_path / "partial.bin", expected)
        cdir = tmp_path / "c"
        cdir.mkdir()
        outdir = tmp_path / "out"
        outdir.mkdir()
        size = max(DEFAULT_CONTAINER_SIZE, partial_size * 4 + MINIMAL_CONTAINER_SIZE)

        create_container(cdir, [src], size=size)
        extract_files(cdir, outdir, files=["partial.bin"])

        actual = (outdir / "partial.bin").read_bytes()
        assert len(actual) == len(expected), (
            f"Partial-last-block size mismatch: expected {len(expected)}, got {len(actual)}"
        )
        assert actual == expected, (
            "Partial-last-block content mismatch in roundtrip"
        )

    def test_three_block_file_roundtrip(self, tmp_path):
        expected = bytes(i & 0xFF for i in range(BLOCK_SIZE * 3))
        src = make_file_with_bytes(tmp_path / "threeblocks.bin", expected)
        cdir = tmp_path / "c"
        cdir.mkdir()
        outdir = tmp_path / "out"
        outdir.mkdir()
        size = max(DEFAULT_CONTAINER_SIZE, BLOCK_SIZE * 12 + MINIMAL_CONTAINER_SIZE)

        create_container(cdir, [src], size=size)
        extract_files(cdir, outdir, files=["threeblocks.bin"])

        actual = (outdir / "threeblocks.bin").read_bytes()
        assert actual == expected, (
            "Three-block file content mismatch in roundtrip"
        )


# ---------------------------------------------------------------------------
# Create → add → extract roundtrip
# ---------------------------------------------------------------------------

class TestRoundtripWithAdd:

    def test_create_add_extract_roundtrip(self, tmp_path):
        """Create with file A, then add file B, extract both."""
        cdir = tmp_path / "c"
        cdir.mkdir()
        outdir = tmp_path / "out"
        outdir.mkdir()
        size = 8 * 1024 * 1024

        data_a = b"File A data: " + bytes(range(100))
        data_b = b"File B data: " + bytes(range(100, 200))

        src_a = make_file_with_bytes(tmp_path / "a.bin", data_a)
        src_b = make_file_with_bytes(tmp_path / "b.bin", data_b)

        create_container(cdir, [src_a], size=size)
        add_file(cdir, src_b)
        extract_files(cdir, outdir, files=None)

        assert (outdir / "a.bin").read_bytes() == data_a, (
            "File A content corrupted after add + extract-all"
        )
        assert (outdir / "b.bin").read_bytes() == data_b, (
            "File B (added later) content incorrect after extract-all"
        )

    def test_create_two_adds_extract_all_correct(self, tmp_path):
        cdir = tmp_path / "c"
        cdir.mkdir()
        outdir = tmp_path / "out"
        outdir.mkdir()
        size = 8 * 1024 * 1024

        contents = {
            "p1.bin": bytes([0x11] * 200),
            "p2.bin": bytes([0x22] * 300),
            "p3.bin": bytes([0x33] * 400),
        }
        names = list(contents.keys())

        first = make_file_with_bytes(tmp_path / names[0], contents[names[0]])
        create_container(cdir, [first], size=size)

        for name in names[1:]:
            p = make_file_with_bytes(tmp_path / name, contents[name])
            add_file(cdir, p)

        extract_files(cdir, outdir, files=None)

        for name, expected in contents.items():
            actual = (outdir / name).read_bytes()
            assert actual == expected, (
                f"Content mismatch for '{name}' in create+two-adds roundtrip"
            )

    def test_large_file_add_small_file_roundtrip(self, tmp_path):
        """Large multi-block file created first, small file added, both extracted intact."""
        cdir = tmp_path / "c"
        cdir.mkdir()
        outdir = tmp_path / "out"
        outdir.mkdir()
        size = 16 * 1024 * 1024

        large_data = bytes(i & 0xFF for i in range(BLOCK_SIZE * 2 + 111))
        small_data = b"\xDE\xAD\xBE\xEF" * 16

        large_src = make_file_with_bytes(tmp_path / "large.bin", large_data)
        small_src = make_file_with_bytes(tmp_path / "small.bin", small_data)

        create_container(cdir, [large_src], size=size)
        add_file(cdir, small_src)
        extract_files(cdir, outdir, files=None)

        assert (outdir / "large.bin").read_bytes() == large_data, (
            "Large file corrupted after adding small file"
        )
        assert (outdir / "small.bin").read_bytes() == small_data, (
            "Small file (added after large) incorrect content"
        )


# ---------------------------------------------------------------------------
# Password sensitivity
# ---------------------------------------------------------------------------

class TestRoundtripPasswordSensitivity:
    """Verify that different passwords produce independent, correct containers."""

    def test_different_passwords_produce_independent_containers(self, tmp_path):
        """
        Create two containers from the same source file but with different passwords.
        Both must produce correct output when decrypted with their own password.
        """
        cdir1 = tmp_path / "c1"
        cdir1.mkdir()
        cdir2 = tmp_path / "c2"
        cdir2.mkdir()
        outdir1 = tmp_path / "out1"
        outdir1.mkdir()
        outdir2 = tmp_path / "out2"
        outdir2.mkdir()

        expected = b"same source content"
        src = make_file_with_bytes(tmp_path / "shared.bin", expected)

        create_container(cdir1, [src], password="password_alpha")
        create_container(cdir2, [src], password="password_beta")

        extract_files(cdir1, outdir1, files=["shared.bin"], password="password_alpha")
        extract_files(cdir2, outdir2, files=["shared.bin"], password="password_beta")

        assert (outdir1 / "shared.bin").read_bytes() == expected, (
            "Container 1 (alpha password) extracted content mismatch"
        )
        assert (outdir2 / "shared.bin").read_bytes() == expected, (
            "Container 2 (beta password) extracted content mismatch"
        )

    def test_special_characters_in_password(self, tmp_path):
        """A password with special characters must work correctly end-to-end."""
        cdir = tmp_path / "c"
        cdir.mkdir()
        outdir = tmp_path / "out"
        outdir.mkdir()
        password = "P@ssw0rd!#$%^&*()-_=+[]{}|;:,.<>?"

        expected = b"secret content with special password"
        src = make_file_with_bytes(tmp_path / "secure.bin", expected)

        create_container(cdir, [src], password=password)
        extract_files(cdir, outdir, files=["secure.bin"], password=password)

        actual = (outdir / "secure.bin").read_bytes()
        assert actual == expected, (
            "Content mismatch when using special-character password"
        )

    def test_long_password_roundtrip(self, tmp_path):
        """A 128-character password must work correctly."""
        cdir = tmp_path / "c"
        cdir.mkdir()
        outdir = tmp_path / "out"
        outdir.mkdir()
        password = "A" * 128

        expected = b"content with a very long password"
        src = make_file_with_bytes(tmp_path / "long_pw.bin", expected)

        create_container(cdir, [src], password=password)
        extract_files(cdir, outdir, files=["long_pw.bin"], password=password)

        actual = (outdir / "long_pw.bin").read_bytes()
        assert actual == expected, (
            "Content mismatch when using 128-character password"
        )
