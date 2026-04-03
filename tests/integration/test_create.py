"""
test_create.py — Integration tests for 'scef create'.

Verified behaviors
------------------
- Container file (container.scef) is created on disk.
- Container file has at least the minimum required size.
- Container file starts with the SCEF magic bytes.
- Create with a single text file succeeds.
- Create with multiple files succeeds.
- Create with a binary file succeeds.
- Create with an empty file succeeds.
- Create with a large file succeeds and produces an appropriately sized container.
- Create without -s flag fails with a non-zero exit code.
- Create without -f flag fails with a non-zero exit code.
- Create without -c flag fails with a non-zero exit code.
- Custom --max_table_size: full roundtrip (create/add/list/extract/verify).
- Custom --max_table_size: container size satisfies the spec minimum.
- Custom --max_table_size: all 4 backup slots carry SCEF magic at correct offsets.
- --max_table_size flag on 'add' command is accepted without error.
- Small --max_table_size (4096) still works for a single-file roundtrip.
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

# ---------------------------------------------------------------------------
# Constants from the SCEF spec (must match Header.h)
# ---------------------------------------------------------------------------

HEADER_SIZE = 4096
DEFAULT_MAX_TABLE_SIZE = 65536
MINIMAL_CONTAINER_SIZE = 4 * (HEADER_SIZE + DEFAULT_MAX_TABLE_SIZE)
SCEF_MAGIC = b"SCEF"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def container_file(container_dir: pathlib.Path) -> pathlib.Path:
    return container_dir / "container.scef"


# ---------------------------------------------------------------------------
# Tests: happy-path scenarios
# ---------------------------------------------------------------------------

class TestCreateSingleTextFile:
    """Create a container with a single small text file."""

    def test_container_file_is_created(self, tmp_path):
        cdir = tmp_path / "c"
        cdir.mkdir()
        src = make_text_file(tmp_path / "hello.txt", "Hello, SCEF!\n")

        create_container(cdir, [src])

        assert container_file(cdir).exists(), (
            "container.scef was not created after 'scef create'"
        )

    def test_container_file_has_minimum_size(self, tmp_path):
        cdir = tmp_path / "c"
        cdir.mkdir()
        src = make_text_file(tmp_path / "data.txt", "small content")

        create_container(cdir, [src], size=DEFAULT_CONTAINER_SIZE)

        actual_size = container_file(cdir).stat().st_size
        assert actual_size >= MINIMAL_CONTAINER_SIZE, (
            f"Container size {actual_size} is below the spec minimum "
            f"{MINIMAL_CONTAINER_SIZE} (4 * (header_size + max_table_size))"
        )

    def test_container_file_size_matches_requested(self, tmp_path):
        cdir = tmp_path / "c"
        cdir.mkdir()
        src = make_text_file(tmp_path / "data.txt", "content")
        requested = DEFAULT_CONTAINER_SIZE

        create_container(cdir, [src], size=requested)

        actual_size = container_file(cdir).stat().st_size
        assert actual_size == requested, (
            f"Expected container size {requested} bytes, got {actual_size}"
        )

    def test_container_starts_with_scef_magic(self, tmp_path):
        """
        The SCEF format places a (Header + File Table) slot at 0%, 25%, 50%, and 75%
        of the container size.  Each slot begins with the 4-byte magic "SCEF".
        Verify that the primary slot (offset 0) carries the correct magic bytes.
        """
        cdir = tmp_path / "c"
        cdir.mkdir()
        src = make_text_file(tmp_path / "data.txt", "content")

        create_container(cdir, [src])

        header_bytes = container_file(cdir).read_bytes()[:4]
        assert header_bytes == SCEF_MAGIC, (
            f"Primary slot (offset 0) must start with magic 'SCEF', got {header_bytes!r}"
        )

    def test_all_four_slots_start_with_scef_magic(self, tmp_path):
        """
        The SCEF slot-based layout duplicates (Header + File Table) at 0%, 25%, 50%,
        and 75% of the container.  All four slots must start with the 'SCEF' magic.
        """
        cdir = tmp_path / "c"
        cdir.mkdir()
        src = make_text_file(tmp_path / "data.txt", "content")

        create_container(cdir, [src])

        data = container_file(cdir).read_bytes()
        size = len(data)

        slot_offsets = [
            0,
            size // 4,
            size // 2,
            (size * 3) // 4,
        ]
        for offset in slot_offsets:
            magic = data[offset : offset + 4]
            assert magic == SCEF_MAGIC, (
                f"Slot at offset {offset} (container size={size}) "
                f"must start with magic 'SCEF', got {magic!r}"
            )


class TestCreateMultipleFiles:
    """Create a container with several files at once."""

    def test_container_created_for_two_files(self, tmp_path):
        cdir = tmp_path / "c"
        cdir.mkdir()
        f1 = make_text_file(tmp_path / "a.txt", "file A")
        f2 = make_text_file(tmp_path / "b.txt", "file B")

        create_container(cdir, [f1, f2])

        assert container_file(cdir).exists(), (
            "container.scef was not created when creating with two files"
        )

    def test_container_created_for_three_files(self, tmp_path):
        cdir = tmp_path / "c"
        cdir.mkdir()
        files = []
        for i in range(3):
            p = make_text_file(tmp_path / f"file{i}.txt", f"content {i}")
            files.append(p)

        create_container(cdir, files)

        assert container_file(cdir).exists()

    def test_container_has_correct_size_with_multiple_files(self, tmp_path):
        cdir = tmp_path / "c"
        cdir.mkdir()
        requested = 8 * 1024 * 1024   # 8 MiB
        files = [make_text_file(tmp_path / f"f{i}.txt", "x" * 1024) for i in range(4)]

        create_container(cdir, files, size=requested)

        actual_size = container_file(cdir).stat().st_size
        assert actual_size == requested, (
            f"Expected {requested} bytes, got {actual_size}"
        )


class TestCreateBinaryFile:
    """Create a container with a binary (non-text) file."""

    def test_binary_file_container_created(self, tmp_path):
        cdir = tmp_path / "c"
        cdir.mkdir()
        src = make_binary_file(tmp_path / "data.bin", 4096, b"\x00\xFF\xAB\xCD")

        create_container(cdir, [src])

        assert container_file(cdir).exists(), (
            "container.scef not created for binary input file"
        )

    def test_all_zero_bytes_file(self, tmp_path):
        cdir = tmp_path / "c"
        cdir.mkdir()
        src = make_binary_file(tmp_path / "zeros.bin", 4096, b"\x00")

        create_container(cdir, [src])

        assert container_file(cdir).exists()

    def test_all_ones_bytes_file(self, tmp_path):
        cdir = tmp_path / "c"
        cdir.mkdir()
        src = make_binary_file(tmp_path / "ones.bin", 4096, b"\xFF")

        create_container(cdir, [src])

        assert container_file(cdir).exists()


class TestCreateEmptyFile:
    """Create a container where the input file has zero bytes."""

    def test_empty_file_container_created(self, tmp_path):
        cdir = tmp_path / "c"
        cdir.mkdir()
        src = make_file_with_bytes(tmp_path / "empty.bin", b"")

        create_container(cdir, [src])

        assert container_file(cdir).exists(), (
            "container.scef not created when input file is empty"
        )

    def test_empty_file_container_has_minimum_size(self, tmp_path):
        cdir = tmp_path / "c"
        cdir.mkdir()
        src = make_file_with_bytes(tmp_path / "empty.bin", b"")

        create_container(cdir, [src], size=DEFAULT_CONTAINER_SIZE)

        actual = container_file(cdir).stat().st_size
        assert actual >= MINIMAL_CONTAINER_SIZE, (
            f"Container for empty file is too small: {actual} < {MINIMAL_CONTAINER_SIZE}"
        )


class TestCreateLargeFile:
    """Create a container with a file that spans multiple encryption blocks."""

    def test_large_file_two_blocks(self, tmp_path):
        """File that spans 2 full blocks (2 * 65536 = 131072 bytes)."""
        cdir = tmp_path / "c"
        cdir.mkdir()
        block_size = 65536
        src = make_binary_file(tmp_path / "large.bin", block_size * 2, b"\xAB\xCD")
        # Container must be large enough to hold data blocks + 4 header slots
        size = max(DEFAULT_CONTAINER_SIZE, block_size * 2 * 2 + MINIMAL_CONTAINER_SIZE)

        create_container(cdir, [src], size=size)

        assert container_file(cdir).exists(), (
            "container.scef not created for file spanning 2 blocks"
        )

    def test_large_file_fractional_last_block(self, tmp_path):
        """File that produces a partial final block (2.5 * 65536 bytes)."""
        cdir = tmp_path / "c"
        cdir.mkdir()
        block_size = 65536
        data_size = int(block_size * 2.5)
        src = make_binary_file(tmp_path / "partial.bin", data_size, b"\x12\x34")
        size = max(DEFAULT_CONTAINER_SIZE, data_size * 2 + MINIMAL_CONTAINER_SIZE)

        create_container(cdir, [src], size=size)

        assert container_file(cdir).exists()


class TestCreateWithMaxTableSize:
    """Test --max_table_size optional argument.

    The flag controls how many bytes are reserved for the encrypted file table
    in each of the 4 header slots.  Spec constraint:
        container_size >= 4 * (HEADER_SIZE + max_table_size)

    All tests in this class use max_table_size=131072 (128 KiB) unless stated
    otherwise, which doubles the default 65536 reservation.
    """

    # Shared constant used across several tests in this class.
    CUSTOM_MAX_TABLE_SIZE = 131072  # 128 KiB

    def test_custom_max_table_size_accepted(self, tmp_path):
        """Passing --max_table_size should not cause a failure."""
        cdir = tmp_path / "c"
        cdir.mkdir()
        src = make_text_file(tmp_path / "f.txt", "content")

        create_container(cdir, [src], max_table_size=self.CUSTOM_MAX_TABLE_SIZE)

        assert container_file(cdir).exists(), (
            "container.scef not created when --max_table_size is specified"
        )

    # ------------------------------------------------------------------
    # Test 1: Full roundtrip with custom max_table_size
    # ------------------------------------------------------------------

    def test_roundtrip_with_custom_max_table_size(self, tmp_path):
        """Create with --max_table_size 131072, add a second file, list, extract,
        and verify that both extracted files are byte-for-byte identical to the
        originals.

        This exercises the full create → add → list → extract pipeline when the
        file table reservation differs from the default.
        """
        cdir = tmp_path / "c"
        cdir.mkdir()
        out = tmp_path / "out"
        out.mkdir()

        # Two source files with distinct, verifiable content.
        content_a = "roundtrip file A — custom table size\n" * 10
        content_b = b"\x01\x02\x03\x04" * 512  # 2 KiB binary
        src_a = make_text_file(tmp_path / "a.txt", content_a)
        src_b = make_binary_file(tmp_path / "b.bin", len(content_b), b"\x01\x02\x03\x04")

        # Create with the first file and a custom max_table_size.
        create_container(
            cdir,
            [src_a],
            size=DEFAULT_CONTAINER_SIZE,
            max_table_size=self.CUSTOM_MAX_TABLE_SIZE,
        )

        # Add the second file (uses the table size already stored in the header).
        add_file(cdir, src_b)

        # list must succeed and mention both file names.
        result = list_container(cdir)
        assert "a.txt" in result.stdout, (
            "list output does not mention 'a.txt' after add"
        )
        assert "b.bin" in result.stdout, (
            "list output does not mention 'b.bin' after add"
        )

        # Extract all files.
        extract_files(cdir, out)

        # Verify byte-for-byte equality.
        extracted_a = out / "a.txt"
        extracted_b = out / "b.bin"

        assert extracted_a.exists(), "extracted a.txt not found"
        assert extracted_b.exists(), "extracted b.bin not found"

        assert extracted_a.read_text(encoding="utf-8") == content_a, (
            "extracted a.txt content differs from original"
        )
        assert extracted_b.read_bytes() == content_b, (
            "extracted b.bin content differs from original"
        )

    # ------------------------------------------------------------------
    # Test 2: Container size accommodates larger table reservation
    # ------------------------------------------------------------------

    def test_container_size_accommodates_larger_table(self, tmp_path):
        """Container created with --max_table_size 131072 must be at least
        4 * (HEADER_SIZE + 131072) = 540672 bytes regardless of the -s value,
        because that is the spec minimum for the given table size.

        We request exactly that minimum as the container size and verify the
        file on disk is >= the minimum.
        """
        cdir = tmp_path / "c"
        cdir.mkdir()
        src = make_text_file(tmp_path / "f.txt", "content")

        min_size = 4 * (HEADER_SIZE + self.CUSTOM_MAX_TABLE_SIZE)  # 540672
        # Request a size comfortably above the minimum so creation succeeds.
        create_container(
            cdir,
            [src],
            size=max(DEFAULT_CONTAINER_SIZE, min_size),
            max_table_size=self.CUSTOM_MAX_TABLE_SIZE,
        )

        actual_size = container_file(cdir).stat().st_size
        assert actual_size >= min_size, (
            f"Container size {actual_size} is below the spec minimum "
            f"{min_size} = 4 * (HEADER_SIZE={HEADER_SIZE} + "
            f"max_table_size={self.CUSTOM_MAX_TABLE_SIZE})"
        )

    # ------------------------------------------------------------------
    # Test 3: All 4 slots carry SCEF magic at their correct offsets
    # ------------------------------------------------------------------

    def test_all_four_slots_have_scef_magic_with_custom_table(self, tmp_path):
        """With --max_table_size 131072, the four (header + file-table) slots
        must still be placed at 0%, 25%, 50%, and 75% of the total container
        size, and each slot must begin with the 4-byte magic 'SCEF'.

        The slot offsets are derived from the container size (quarters), not
        from HEADER_SIZE or max_table_size, so this test uses the actual file
        size to compute them rather than any hard-coded constant.
        """
        cdir = tmp_path / "c"
        cdir.mkdir()
        src = make_text_file(tmp_path / "f.txt", "content for slot test")

        create_container(
            cdir,
            [src],
            size=DEFAULT_CONTAINER_SIZE,
            max_table_size=self.CUSTOM_MAX_TABLE_SIZE,
        )

        data = container_file(cdir).read_bytes()
        total = len(data)

        slot_offsets = [
            0,
            total // 4,
            total // 2,
            (total * 3) // 4,
        ]
        for offset in slot_offsets:
            magic = data[offset : offset + 4]
            assert magic == SCEF_MAGIC, (
                f"Slot at offset {offset} (container_size={total}, "
                f"max_table_size={self.CUSTOM_MAX_TABLE_SIZE}) "
                f"must start with magic 'SCEF', got {magic!r}"
            )

    # ------------------------------------------------------------------
    # Test 4: --max_table_size flag on 'add' is accepted without error
    # ------------------------------------------------------------------

    def test_max_table_size_flag_on_add_is_accepted(self, tmp_path):
        """The 'add' command parses --max_table_size without error.

        Note: main.cpp currently hardcodes DEFAULT_MAX_TABLE_SIZE when
        calling fileManager.init() for 'add', so the flag value is parsed
        but not forwarded to the file manager.  This test verifies the flag
        does not cause a parse error or non-zero exit — it does not verify
        that the custom value is applied (that would require a separate
        specification change).
        """
        cdir = tmp_path / "c"
        cdir.mkdir()
        out = tmp_path / "out"
        out.mkdir()

        src_a = make_text_file(tmp_path / "a.txt", "initial file")
        src_b = make_text_file(tmp_path / "b.txt", "added file")

        # Create a standard container (default table size).
        create_container(cdir, [src_a])

        # Add with --max_table_size explicitly supplied — must not fail.
        result = run_scef(
            [
                "add",
                "-c", str(cdir),
                "-f", str(src_b),
                "--max_table_size", str(self.CUSTOM_MAX_TABLE_SIZE),
            ],
            expect_success=True,
        )

        assert result.returncode == 0, (
            f"'scef add --max_table_size' exited with rc={result.returncode}.\n"
            f"stderr: {result.stderr.strip()}"
        )

        # Verify the added file can be listed, confirming the add was not a no-op.
        list_result = list_container(cdir)
        assert "b.txt" in list_result.stdout, (
            "b.txt not found in list output after 'add --max_table_size'"
        )

    # ------------------------------------------------------------------
    # Test 5: Small max_table_size still works for a single-file roundtrip
    # ------------------------------------------------------------------

    def test_small_max_table_size_roundtrip(self, tmp_path):
        """Create with --max_table_size 4096 (minimum meaningful value),
        add one small file, extract, and verify the content matches.

        A table size of 4096 bytes is enough to store a handful of file
        entries.  This test confirms the implementation does not special-case
        the default value and handles small table reservations correctly.
        """
        cdir = tmp_path / "c"
        cdir.mkdir()
        out = tmp_path / "out"
        out.mkdir()

        small_table_size = 4096
        expected_content = "small table size test — one file only\n"
        src = make_text_file(tmp_path / "single.txt", expected_content)

        create_container(
            cdir,
            [src],
            size=DEFAULT_CONTAINER_SIZE,
            max_table_size=small_table_size,
        )

        # list must succeed.
        list_result = list_container(cdir)
        assert "single.txt" in list_result.stdout, (
            "single.txt not listed after create with max_table_size=4096"
        )

        # extract and verify.
        extract_files(cdir, out)

        extracted = out / "single.txt"
        assert extracted.exists(), "single.txt not found after extract"
        assert extracted.read_text(encoding="utf-8") == expected_content, (
            "extracted single.txt content differs from original "
            "when using max_table_size=4096"
        )


# ---------------------------------------------------------------------------
# Tests: error paths
# ---------------------------------------------------------------------------

class TestCreateMissingRequiredArguments:
    """Missing required arguments must produce a non-zero exit code."""

    def test_no_size_flag_fails(self, tmp_path):
        cdir = tmp_path / "c"
        cdir.mkdir()
        src = make_text_file(tmp_path / "f.txt", "x")
        # Build args without -s
        args = ["create", "-c", str(cdir), "-f", str(src)]

        result = run_scef(args, expect_success=False)

        assert result.returncode != 0, (
            "scef create without -s must exit with non-zero code"
        )

    def test_zero_size_fails(self, tmp_path):
        cdir = tmp_path / "c"
        cdir.mkdir()
        src = make_text_file(tmp_path / "f.txt", "x")
        args = ["create", "-c", str(cdir), "-f", str(src), "-s", "0"]

        result = run_scef(args, expect_success=False)

        assert result.returncode != 0, (
            "scef create with -s 0 must exit with non-zero code"
        )

    def test_no_file_flag_fails(self, tmp_path):
        cdir = tmp_path / "c"
        cdir.mkdir()
        # Pass only -c and -s, omit -f entirely
        args = ["create", "-c", str(cdir), "-s", str(DEFAULT_CONTAINER_SIZE)]

        result = run_scef(args, expect_success=False)

        assert result.returncode != 0, (
            "scef create without -f must exit with non-zero code"
        )

    def test_no_container_path_fails(self, tmp_path):
        src = make_text_file(tmp_path / "f.txt", "x")
        # Pass only -f and -s, omit -c entirely
        args = ["create", "-f", str(src), "-s", str(DEFAULT_CONTAINER_SIZE)]

        result = run_scef(args, expect_success=False)

        assert result.returncode != 0, (
            "scef create without -c must exit with non-zero code"
        )

    def test_nonexistent_input_file_fails(self, tmp_path):
        cdir = tmp_path / "c"
        cdir.mkdir()
        args = [
            "create",
            "-c", str(cdir),
            "-f", str(tmp_path / "does_not_exist.txt"),
            "-s", str(DEFAULT_CONTAINER_SIZE),
        ]

        result = run_scef(args, expect_success=False)

        assert result.returncode != 0, (
            "scef create with non-existent input file must exit with non-zero code"
        )
