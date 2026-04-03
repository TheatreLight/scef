"""
test_add.py — Integration tests for 'scef add'.

Verified behaviors
------------------
- Adding a file to an existing container exits with code 0.
- After add, 'scef list' reports more files than before.
- After add, the newly added file is extractable.
- The previously present file is still extractable after add.
- Adding multiple files sequentially works correctly.
- Adding a binary file to a container works.
- Adding an empty file to a container works.
- Adding a file whose content exactly fills one block boundary.
- add on a non-existent container path fails with non-zero exit code.
- add without -f flag fails with non-zero exit code.
- add without -c flag fails with non-zero exit code.
"""

import pathlib
import pytest

from conftest import (
    DEFAULT_PASSWORD,
    DEFAULT_CONTAINER_SIZE,
    create_container,
    add_file,
    list_container,
    extract_files,
    make_text_file,
    make_binary_file,
    make_file_with_bytes,
    run_scef,
)

BLOCK_SIZE = 65536


# ---------------------------------------------------------------------------
# Tests: happy-path
# ---------------------------------------------------------------------------

class TestAddBasic:
    """Basic add: single file added to a fresh container."""

    def test_add_returns_zero(self, tmp_path):
        cdir = tmp_path / "c"
        cdir.mkdir()
        f1 = make_text_file(tmp_path / "first.txt", "initial content")
        create_container(cdir, [f1])

        f2 = make_text_file(tmp_path / "second.txt", "added content")
        result = add_file(cdir, f2)

        assert result.returncode == 0, (
            f"scef add returned non-zero: {result.returncode}\n"
            f"stderr: {result.stderr.strip()}"
        )

    def test_added_file_appears_in_list(self, tmp_path):
        cdir = tmp_path / "c"
        cdir.mkdir()
        f1 = make_text_file(tmp_path / "a.txt", "a")
        create_container(cdir, [f1])

        f2 = make_text_file(tmp_path / "b.txt", "b")
        add_file(cdir, f2)

        result = list_container(cdir)
        assert "b.txt" in result.stdout, (
            f"Added file 'b.txt' not visible in list output:\n{result.stdout}"
        )

    def test_original_file_still_in_list_after_add(self, tmp_path):
        cdir = tmp_path / "c"
        cdir.mkdir()
        f1 = make_text_file(tmp_path / "original.txt", "original")
        create_container(cdir, [f1])

        f2 = make_text_file(tmp_path / "new.txt", "new file")
        add_file(cdir, f2)

        result = list_container(cdir)
        assert "original.txt" in result.stdout, (
            f"Original file disappeared from list after add:\n{result.stdout}"
        )


class TestAddExtractability:
    """After add, files must be extractable with correct content."""

    def test_added_file_extractable(self, tmp_path):
        cdir = tmp_path / "c"
        cdir.mkdir()
        outdir = tmp_path / "out"
        outdir.mkdir()

        f1 = make_text_file(tmp_path / "first.txt", "first file content")
        create_container(cdir, [f1])

        expected = b"second file content"
        f2 = make_file_with_bytes(tmp_path / "second.txt", expected)
        add_file(cdir, f2)

        extract_files(cdir, outdir, files=["second.txt"])

        extracted = (outdir / "second.txt").read_bytes()
        assert extracted == expected, (
            f"Extracted content of added file does not match original.\n"
            f"Expected: {expected!r}\nGot:      {extracted!r}"
        )

    def test_original_file_intact_after_add(self, tmp_path):
        cdir = tmp_path / "c"
        cdir.mkdir()
        outdir = tmp_path / "out"
        outdir.mkdir()

        expected_original = b"original content bytes"
        f1 = make_file_with_bytes(tmp_path / "original.bin", expected_original)
        create_container(cdir, [f1])

        f2 = make_text_file(tmp_path / "newcomer.txt", "new")
        add_file(cdir, f2)

        extract_files(cdir, outdir, files=["original.bin"])

        extracted = (outdir / "original.bin").read_bytes()
        assert extracted == expected_original, (
            f"Original file was corrupted by add.\n"
            f"Expected: {expected_original!r}\nGot: {extracted!r}"
        )


class TestAddMultipleSequential:
    """Multiple sequential add() calls accumulate all files."""

    def test_three_sequential_adds_all_visible(self, tmp_path):
        cdir = tmp_path / "c"
        cdir.mkdir()
        size = 8 * 1024 * 1024  # 8 MiB to have room for 4 files

        f1 = make_text_file(tmp_path / "f1.txt", "content1")
        create_container(cdir, [f1], size=size)

        f2 = make_text_file(tmp_path / "f2.txt", "content2")
        f3 = make_text_file(tmp_path / "f3.txt", "content3")
        add_file(cdir, f2)
        add_file(cdir, f3)

        result = list_container(cdir)
        for name in ("f1.txt", "f2.txt", "f3.txt"):
            assert name in result.stdout, (
                f"File '{name}' not found in list after sequential adds:\n{result.stdout}"
            )

    def test_three_sequential_adds_all_extractable(self, tmp_path):
        cdir = tmp_path / "c"
        cdir.mkdir()
        outdir = tmp_path / "out"
        outdir.mkdir()
        size = 8 * 1024 * 1024

        contents = {
            "s1.bin": b"\x01" * 512,
            "s2.bin": b"\x02" * 512,
            "s3.bin": b"\x03" * 512,
        }

        names = list(contents.keys())
        first_path = make_file_with_bytes(tmp_path / names[0], contents[names[0]])
        create_container(cdir, [first_path], size=size)

        for name in names[1:]:
            p = make_file_with_bytes(tmp_path / name, contents[name])
            add_file(cdir, p)

        extract_files(cdir, outdir, files=list(names))

        for name, expected in contents.items():
            extracted = (outdir / name).read_bytes()
            assert extracted == expected, (
                f"Content mismatch for '{name}' after sequential adds."
            )


class TestAddSpecialFiles:
    """Add binary, empty, and block-boundary files."""

    def test_add_binary_file(self, tmp_path):
        cdir = tmp_path / "c"
        cdir.mkdir()
        f1 = make_text_file(tmp_path / "base.txt", "base")
        create_container(cdir, [f1])

        src = make_binary_file(tmp_path / "binary.bin", 2048, b"\xDE\xAD\xBE\xEF")
        add_file(cdir, src)

        result = list_container(cdir)
        assert "binary.bin" in result.stdout, (
            "Binary file not visible in list after add"
        )

    def test_add_empty_file(self, tmp_path):
        cdir = tmp_path / "c"
        cdir.mkdir()
        f1 = make_text_file(tmp_path / "base.txt", "base")
        create_container(cdir, [f1])

        empty = make_file_with_bytes(tmp_path / "empty.bin", b"")
        add_file(cdir, empty)

        result = list_container(cdir)
        assert "empty.bin" in result.stdout, (
            "Empty file not visible in list after add"
        )

    def test_add_file_exactly_one_block(self, tmp_path):
        """A file whose size equals one encryption block (65536 bytes)."""
        cdir = tmp_path / "c"
        cdir.mkdir()
        size = 16 * 1024 * 1024

        f1 = make_text_file(tmp_path / "base.txt", "base")
        create_container(cdir, [f1], size=size)

        src = make_binary_file(tmp_path / "oneblock.bin", BLOCK_SIZE, b"\xAA\xBB")
        add_file(cdir, src)

        result = list_container(cdir)
        assert "oneblock.bin" in result.stdout, (
            "Block-sized file not visible in list after add"
        )

    def test_add_file_spanning_two_blocks(self, tmp_path):
        """A file that spans exactly 2 full blocks."""
        cdir = tmp_path / "c"
        cdir.mkdir()
        size = 16 * 1024 * 1024

        f1 = make_text_file(tmp_path / "base.txt", "base")
        create_container(cdir, [f1], size=size)

        src = make_binary_file(tmp_path / "twoblocks.bin", BLOCK_SIZE * 2, b"\xCC\xDD")
        add_file(cdir, src)

        result = list_container(cdir)
        assert "twoblocks.bin" in result.stdout, (
            "Two-block file not visible in list after add"
        )


# ---------------------------------------------------------------------------
# Tests: error paths
# ---------------------------------------------------------------------------

class TestAddErrorPaths:
    """add must fail gracefully when called incorrectly."""

    def test_add_to_nonexistent_container_fails(self, tmp_path):
        cdir = tmp_path / "no_container"
        cdir.mkdir()
        src = make_text_file(tmp_path / "f.txt", "x")

        result = run_scef(
            ["add", "-c", str(cdir), "-f", str(src)],
            expect_success=False,
        )

        assert result.returncode != 0, (
            "scef add on non-existent container must fail with non-zero exit code"
        )

    def test_add_without_file_flag_fails(self, tmp_path):
        cdir = tmp_path / "c"
        cdir.mkdir()
        f1 = make_text_file(tmp_path / "base.txt", "base")
        create_container(cdir, [f1])

        result = run_scef(
            ["add", "-c", str(cdir)],
            expect_success=False,
        )

        assert result.returncode != 0, (
            "scef add without -f must fail with non-zero exit code"
        )

    def test_add_without_container_flag_fails(self, tmp_path):
        src = make_text_file(tmp_path / "f.txt", "x")

        result = run_scef(
            ["add", "-f", str(src)],
            expect_success=False,
        )

        assert result.returncode != 0, (
            "scef add without -c must fail with non-zero exit code"
        )

    def test_add_nonexistent_source_file_fails(self, tmp_path):
        cdir = tmp_path / "c"
        cdir.mkdir()
        f1 = make_text_file(tmp_path / "base.txt", "base")
        create_container(cdir, [f1])

        result = run_scef(
            ["add", "-c", str(cdir), "-f", str(tmp_path / "ghost.bin")],
            expect_success=False,
        )

        assert result.returncode != 0, (
            "scef add of a non-existent source file must fail with non-zero exit code"
        )
