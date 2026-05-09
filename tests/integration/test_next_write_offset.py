"""
test_next_write_offset.py — Verify that next_write_offset is persisted across
container reopens.

Spec invariant (FileTable.h:43-44, FileManager::readFilesTable):
  The file table JSON contains a 'next_write_offset' field that tracks the byte
  offset at which the next data block should be written.  After 'scef create'
  or 'scef add', this value must be written to disk (as part of the encrypted
  file table in all 4 slots).  On the next 'scef add' call, the value must be
  read from disk and used — NOT recomputed from scratch.

Why it matters:
  If next_write_offset is not persisted (or not read on reopen), a subsequent
  'scef add' would start writing at offset 0, overwriting the previously stored
  data blocks.  The file table would then point to the old offsets, but the
  data at those offsets is now overwritten with new file data — causing
  authentication failures or wrong content on extract.

  Alternatively, if next_write_offset is recomputed from file entries on every
  open (the spec fallback in FileTable::deserialize), the value should still
  be correct — this test verifies the end-to-end result rather than the internal
  mechanism.

Test approach:
  - Create container with file A.
  - Add file B (uses next_write_offset to know where to write).
  - Extract file A → verify content matches original.
  - Extract file B → verify content matches original.
  - Byte-perfect match for BOTH files proves that neither overwrote the other's
    data blocks.  Any next_write_offset bug would cause one extraction to fail
    or produce wrong content.
"""

import pathlib
import pytest

from conftest import (
    DEFAULT_PASSWORD,
    DEFAULT_CONTAINER_SIZE,
    FAST_KDF_ARGS,
    create_container,
    add_file,
    extract_files,
    list_container,
    make_text_file,
    make_file_with_bytes,
    make_binary_file,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def assert_files_byte_equal(original: pathlib.Path, extracted: pathlib.Path) -> None:
    """Assert that extracted is byte-for-byte identical to original."""
    assert extracted.exists(), (
        f"Extracted file does not exist: {extracted}"
    )
    orig_data = original.read_bytes()
    extr_data = extracted.read_bytes()
    assert len(extr_data) == len(orig_data), (
        f"{extracted.name}: size mismatch — "
        f"expected {len(orig_data)} bytes, got {len(extr_data)} bytes"
    )
    assert extr_data == orig_data, (
        f"{extracted.name}: byte content mismatch — "
        f"first differing byte at index "
        f"{next(i for i, (a, b) in enumerate(zip(extr_data, orig_data)) if a != b)}"
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestNextWriteOffsetPersistence:
    """
    Verify that next_write_offset is correctly persisted and reloaded across
    container opens.
    """

    def test_two_text_files_both_extract_correctly(self, tmp_path):
        """
        Create with file A, add file B, extract both — verify byte-perfect match.

        If next_write_offset was not persisted or read correctly on the add
        operation, file B's data blocks would overwrite file A's data blocks.
        Extracting file A would then either fail (authentication error because
        the data is corrupt) or return file B's content.
        """
        cdir = tmp_path / "c"
        cdir.mkdir()
        outdir = tmp_path / "out"
        outdir.mkdir()

        content_a = "File A content — unique marker A1B2C3D4\n" * 20
        content_b = "File B content — unique marker E5F6G7H8\n" * 20

        src_a = make_text_file(tmp_path / "file_a.txt", content_a)
        src_b = make_text_file(tmp_path / "file_b.txt", content_b)

        # Create with file A only.
        create_container(cdir, [src_a], size=DEFAULT_CONTAINER_SIZE)

        # Add file B (closes and reopens the container internally via the CLI).
        add_file(cdir, src_b)

        # Extract and verify file A.
        extract_files(cdir, outdir, files=["file_a.txt"])
        extracted_a = outdir / "file_a.txt"
        assert_files_byte_equal(src_a, extracted_a)

        # Extract and verify file B.
        extract_files(cdir, outdir, files=["file_b.txt"])
        extracted_b = outdir / "file_b.txt"
        assert_files_byte_equal(src_b, extracted_b)

    def test_two_binary_files_both_extract_correctly(self, tmp_path):
        """
        Same as above but with binary files to ensure no text-encoding coincidences.
        File A uses pattern 0xAB 0xCD, File B uses 0x12 0x34 — easy to distinguish
        if blocks are mixed up.
        """
        cdir = tmp_path / "c"
        cdir.mkdir()
        outdir = tmp_path / "out"
        outdir.mkdir()

        src_a = make_binary_file(tmp_path / "a.bin", 8192, b"\xAB\xCD")
        src_b = make_binary_file(tmp_path / "b.bin", 4096, b"\x12\x34")

        create_container(cdir, [src_a], size=DEFAULT_CONTAINER_SIZE)
        add_file(cdir, src_b)

        extract_files(cdir, outdir, files=["a.bin"])
        assert_files_byte_equal(src_a, outdir / "a.bin")

        extract_files(cdir, outdir, files=["b.bin"])
        assert_files_byte_equal(src_b, outdir / "b.bin")

    def test_three_sequential_adds_all_extract_correctly(self, tmp_path):
        """
        Chain three adds (create + 2 adds) and verify all three files extract
        correctly.  Each add uses next_write_offset from the previous write,
        so the persistence must be correct for all three iterations.
        """
        cdir = tmp_path / "c"
        cdir.mkdir()
        outdir = tmp_path / "out"
        outdir.mkdir()

        contents = {
            "f1.bin": b"\x01\x02\x03" * 100,
            "f2.bin": b"\x04\x05\x06" * 200,
            "f3.bin": b"\x07\x08\x09" * 150,
        }

        src_paths = {}
        for name, data in contents.items():
            p = tmp_path / name
            p.write_bytes(data)
            src_paths[name] = p

        # Create with first file.
        create_container(cdir, [src_paths["f1.bin"]], size=DEFAULT_CONTAINER_SIZE)
        # Add second and third files sequentially.
        add_file(cdir, src_paths["f2.bin"])
        add_file(cdir, src_paths["f3.bin"])

        # Verify all three extract correctly.
        for name, original_data in contents.items():
            extract_files(cdir, outdir, files=[name])
            extracted = outdir / name
            assert extracted.exists(), f"Extracted file {name} not found"
            actual = extracted.read_bytes()
            assert actual == original_data, (
                f"{name}: extracted content does not match original.  "
                f"next_write_offset may not have been persisted correctly "
                f"after the previous add operation."
            )

    def test_list_shows_all_files_after_sequential_adds(self, tmp_path):
        """
        After create + two adds, 'scef list' must show all three files.
        This verifies the file table was correctly updated on each add.
        """
        cdir = tmp_path / "c"
        cdir.mkdir()

        src_a = make_text_file(tmp_path / "alpha.txt", "alpha\n")
        src_b = make_text_file(tmp_path / "beta.txt",  "beta\n")
        src_c = make_text_file(tmp_path / "gamma.txt", "gamma\n")

        create_container(cdir, [src_a], size=DEFAULT_CONTAINER_SIZE)
        add_file(cdir, src_b)
        add_file(cdir, src_c)

        result = list_container(cdir)
        assert result.returncode == 0

        for name in ("alpha.txt", "beta.txt", "gamma.txt"):
            assert name in result.stdout, (
                f"'{name}' not found in 'scef list' output after sequential adds.\n"
                f"stdout: {result.stdout}"
            )

    def test_create_with_multiple_files_extract_all_correct(self, tmp_path):
        """
        Create a container with two files at once.  Both files are written in a
        single create call, so next_write_offset is advanced for each file.
        Verify both extract correctly.

        This tests the initial next_write_offset advancement during create,
        not the persistence across reopens — but it ensures the baseline is
        correct before testing the reopen path.
        """
        cdir = tmp_path / "c"
        cdir.mkdir()
        outdir = tmp_path / "out"
        outdir.mkdir()

        content_a = b"\xAA" * 1024
        content_b = b"\xBB" * 2048

        src_a = tmp_path / "aa.bin"
        src_b = tmp_path / "bb.bin"
        src_a.write_bytes(content_a)
        src_b.write_bytes(content_b)

        create_container(cdir, [src_a, src_b], size=DEFAULT_CONTAINER_SIZE)

        extract_files(cdir, outdir)

        assert (outdir / "aa.bin").read_bytes() == content_a, (
            "aa.bin extracted content does not match original"
        )
        assert (outdir / "bb.bin").read_bytes() == content_b, (
            "bb.bin extracted content does not match original"
        )
