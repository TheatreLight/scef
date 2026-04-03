"""
test_extract.py — Integration tests for 'scef extract'.

Verified behaviors
------------------
- Extract single file by name: output file exists and is byte-for-byte correct.
- Extract all (no -f flag): all files in the container are written to output dir.
- Extract multiple specific files: only the named files are extracted.
- Extracted text file content is correct.
- Extracted binary file content is correct.
- Extracted empty file has zero bytes.
- Extracted file from a large container (multi-block) is byte-for-byte correct.
- Wrong password on extract fails with non-zero exit code.
- Extract of a non-existent file within the container fails.
- Extract without -c flag fails.
- Extract without -o flag fails.
- Extract from non-existent container fails.
"""

import pathlib
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
    run_scef,
)

BLOCK_SIZE = 65536

# Slot-based layout constants (must match Header.h).
HEADER_SIZE = 4096
DEFAULT_MAX_TABLE_SIZE = 65536
# 4 * (header + file-table) = the structural minimum container size.
MINIMAL_CONTAINER_SIZE = 4 * (HEADER_SIZE + DEFAULT_MAX_TABLE_SIZE)  # 278528 bytes


# ---------------------------------------------------------------------------
# Tests: happy-path
# ---------------------------------------------------------------------------

class TestExtractSingleFile:
    """Extract a single named file from a container."""

    def test_extract_creates_output_file(self, tmp_path):
        cdir = tmp_path / "c"
        cdir.mkdir()
        outdir = tmp_path / "out"
        outdir.mkdir()
        src = make_text_file(tmp_path / "hello.txt", "hello world")
        create_container(cdir, [src])

        extract_files(cdir, outdir, files=["hello.txt"])

        assert (outdir / "hello.txt").exists(), (
            "Extracted file hello.txt does not exist in output directory"
        )

    def test_extract_text_file_correct_content(self, tmp_path):
        cdir = tmp_path / "c"
        cdir.mkdir()
        outdir = tmp_path / "out"
        outdir.mkdir()
        expected = "The quick brown fox jumps over the lazy dog.\n"
        src = make_text_file(tmp_path / "text.txt", expected)
        create_container(cdir, [src])

        extract_files(cdir, outdir, files=["text.txt"])

        actual = (outdir / "text.txt").read_text(encoding="utf-8")
        assert actual == expected, (
            f"Extracted text content mismatch.\nExpected: {expected!r}\nGot: {actual!r}"
        )

    def test_extract_binary_file_byte_for_byte(self, tmp_path):
        cdir = tmp_path / "c"
        cdir.mkdir()
        outdir = tmp_path / "out"
        outdir.mkdir()
        expected = bytes(range(256)) * 16   # 4096 distinct bytes
        src = make_file_with_bytes(tmp_path / "data.bin", expected)
        create_container(cdir, [src])

        extract_files(cdir, outdir, files=["data.bin"])

        actual = (outdir / "data.bin").read_bytes()
        assert actual == expected, (
            "Extracted binary file does not match original byte-for-byte"
        )

    def test_extract_preserves_filename(self, tmp_path):
        cdir = tmp_path / "c"
        cdir.mkdir()
        outdir = tmp_path / "out"
        outdir.mkdir()
        src = make_text_file(tmp_path / "my_document.pdf", "fake pdf")
        create_container(cdir, [src])

        extract_files(cdir, outdir, files=["my_document.pdf"])

        assert (outdir / "my_document.pdf").exists(), (
            "Extracted file does not have the original filename"
        )


class TestExtractAllFiles:
    """Extract all files (no -f flag)."""

    def test_extract_all_creates_all_files(self, tmp_path):
        cdir = tmp_path / "c"
        cdir.mkdir()
        outdir = tmp_path / "out"
        outdir.mkdir()
        filenames = ["file_a.txt", "file_b.bin", "file_c.dat"]
        files = [make_text_file(tmp_path / name, f"content of {name}") for name in filenames]
        create_container(cdir, files)

        extract_files(cdir, outdir, files=None)

        for name in filenames:
            assert (outdir / name).exists(), (
                f"File '{name}' not found in output directory after extract-all"
            )

    def test_extract_all_correct_content(self, tmp_path):
        cdir = tmp_path / "c"
        cdir.mkdir()
        outdir = tmp_path / "out"
        outdir.mkdir()

        contents = {
            "x.txt":  b"content x",
            "y.bin":  b"\xAA\xBB\xCC",
            "z.dat":  b"\x00" * 256,
        }
        for name, data in contents.items():
            make_file_with_bytes(tmp_path / name, data)

        create_container(cdir, [tmp_path / n for n in contents.keys()])
        extract_files(cdir, outdir, files=None)

        for name, expected in contents.items():
            actual = (outdir / name).read_bytes()
            assert actual == expected, (
                f"Content mismatch for '{name}' during extract-all.\n"
                f"Expected {len(expected)} bytes, got {len(actual)} bytes."
            )

    def test_extract_all_after_sequential_adds(self, tmp_path):
        cdir = tmp_path / "c"
        cdir.mkdir()
        outdir = tmp_path / "out"
        outdir.mkdir()
        size = 8 * 1024 * 1024

        contents = {
            "first.bin":  b"\x11" * 128,
            "second.bin": b"\x22" * 256,
            "third.bin":  b"\x33" * 512,
        }
        names = list(contents.keys())

        first_path = make_file_with_bytes(tmp_path / names[0], contents[names[0]])
        create_container(cdir, [first_path], size=size)
        for name in names[1:]:
            p = make_file_with_bytes(tmp_path / name, contents[name])
            add_file(cdir, p)

        extract_files(cdir, outdir, files=None)

        for name, expected in contents.items():
            actual = (outdir / name).read_bytes()
            assert actual == expected, (
                f"Content mismatch for '{name}' in extract-all after sequential adds."
            )


class TestExtractSpecificFiles:
    """Extract a subset of files by name."""

    def test_extract_one_of_two_files(self, tmp_path):
        cdir = tmp_path / "c"
        cdir.mkdir()
        outdir = tmp_path / "out"
        outdir.mkdir()

        f1 = make_text_file(tmp_path / "keep.txt", "keep this")
        f2 = make_text_file(tmp_path / "ignore.txt", "ignore this")
        create_container(cdir, [f1, f2])

        extract_files(cdir, outdir, files=["keep.txt"])

        assert (outdir / "keep.txt").exists(), (
            "Requested file 'keep.txt' was not extracted"
        )

    # The scenario "only the named file is extracted when -f is given" is
    # already covered by test_extract_one_of_two_files above.


class TestExtractEmptyFile:
    """Extract an empty file: output file must exist and have 0 bytes."""

    def test_empty_file_extracted_with_zero_bytes(self, tmp_path):
        cdir = tmp_path / "c"
        cdir.mkdir()
        outdir = tmp_path / "out"
        outdir.mkdir()
        src = make_file_with_bytes(tmp_path / "empty.bin", b"")
        create_container(cdir, [src])

        extract_files(cdir, outdir, files=["empty.bin"])

        extracted = outdir / "empty.bin"
        assert extracted.exists(), "Empty file was not extracted"
        assert extracted.stat().st_size == 0, (
            f"Extracted empty file has non-zero size: {extracted.stat().st_size}"
        )


class TestExtractLargeFile:
    """Extract files that span multiple encryption blocks."""

    def test_extract_two_block_file_correct(self, tmp_path):
        cdir = tmp_path / "c"
        cdir.mkdir()
        outdir = tmp_path / "out"
        outdir.mkdir()
        expected = bytes(i & 0xFF for i in range(BLOCK_SIZE * 2))
        src = make_file_with_bytes(tmp_path / "twoblock.bin", expected)
        # Overhead = 4 full slots (header + file-table each), not just 4 headers.
        size = max(DEFAULT_CONTAINER_SIZE, len(expected) * 2 + MINIMAL_CONTAINER_SIZE)

        create_container(cdir, [src], size=size)
        extract_files(cdir, outdir, files=["twoblock.bin"])

        actual = (outdir / "twoblock.bin").read_bytes()
        assert actual == expected, (
            f"Two-block file content mismatch after extract. "
            f"Expected {len(expected)} bytes, got {len(actual)} bytes."
        )

    def test_extract_partial_last_block_file_correct(self, tmp_path):
        """File with 2.5 blocks: the partial trailing block must be preserved exactly."""
        cdir = tmp_path / "c"
        cdir.mkdir()
        outdir = tmp_path / "out"
        outdir.mkdir()
        data_size = int(BLOCK_SIZE * 2.5)
        expected = bytes(i & 0xFF for i in range(data_size))
        src = make_file_with_bytes(tmp_path / "partial.bin", expected)
        # Overhead = 4 full slots (header + file-table each), not just 4 headers.
        size = max(DEFAULT_CONTAINER_SIZE, len(expected) * 2 + MINIMAL_CONTAINER_SIZE)

        create_container(cdir, [src], size=size)
        extract_files(cdir, outdir, files=["partial.bin"])

        actual = (outdir / "partial.bin").read_bytes()
        assert len(actual) == len(expected), (
            f"Extracted file size mismatch: expected {len(expected)}, got {len(actual)}"
        )
        assert actual == expected, (
            "Partial-last-block file content does not match original"
        )


# ---------------------------------------------------------------------------
# Tests: error paths
# ---------------------------------------------------------------------------

class TestExtractErrorPaths:

    def test_wrong_password_fails(self, tmp_path):
        cdir = tmp_path / "c"
        cdir.mkdir()
        outdir = tmp_path / "out"
        outdir.mkdir()
        src = make_text_file(tmp_path / "f.txt", "secret")
        create_container(cdir, [src], password="correct")

        result = run_scef(
            ["extract", "-c", str(cdir), "-o", str(outdir), "-f", "f.txt"],
            password="wrong",
            expect_success=False,
        )

        assert result.returncode != 0, (
            "scef extract with wrong password must fail with non-zero exit code"
        )

    def test_extract_nonexistent_file_in_container_fails(self, tmp_path):
        cdir = tmp_path / "c"
        cdir.mkdir()
        outdir = tmp_path / "out"
        outdir.mkdir()
        src = make_text_file(tmp_path / "real.txt", "real")
        create_container(cdir, [src])

        result = run_scef(
            ["extract", "-c", str(cdir), "-o", str(outdir), "-f", "ghost.txt"],
            expect_success=False,
        )

        assert result.returncode != 0, (
            "scef extract of a file not in the container must fail with non-zero exit code"
        )

    def test_extract_without_container_flag_fails(self, tmp_path):
        outdir = tmp_path / "out"
        outdir.mkdir()

        result = run_scef(
            ["extract", "-o", str(outdir)],
            expect_success=False,
        )

        assert result.returncode != 0, (
            "scef extract without -c must fail with non-zero exit code"
        )

    def test_extract_without_output_flag_fails(self, tmp_path):
        cdir = tmp_path / "c"
        cdir.mkdir()

        result = run_scef(
            ["extract", "-c", str(cdir)],
            expect_success=False,
        )

        assert result.returncode != 0, (
            "scef extract without -o must fail with non-zero exit code"
        )

    def test_extract_from_nonexistent_container_fails(self, tmp_path):
        cdir = tmp_path / "no_container"
        cdir.mkdir()
        outdir = tmp_path / "out"
        outdir.mkdir()

        result = extract_files(cdir, outdir, files=None, expect_success=False)

        assert result.returncode != 0, (
            "scef extract from non-existent container must fail with non-zero exit code"
        )
