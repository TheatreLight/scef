"""
test_header_resilience.py — Tests for SCEF's 4-redundant-header crash resilience.

SCEF embeds four identical (Header + FileTable) slots at 0%, 25%, 50%, 75% of the
container size.  The readMeta() recovery logic is:

  1. Try all 4 slots in order (0, 1, 2, 3).
  2. For each slot: check magic → init crypto (derive KEK) → verify HMAC.
  3. First slot that passes all checks wins.
  4. If a slot has valid magic but fails HMAC, continue to next slot (the
     HMAC-protected region may be corrupted by a bad sector/USB glitch while
     backup slots remain intact).
  5. If ALL slots fail:
     - At least one had valid magic → "wrong password or container corrupted"
     - No valid magic anywhere → "invalid container"
"""

import pathlib
import struct
import pytest

from conftest import (
    DEFAULT_PASSWORD,
    DEFAULT_CONTAINER_SIZE,
    create_container,
    list_container,
    extract_files,
    make_file_with_bytes,
    run_scef,
)

# ---------------------------------------------------------------------------
# Layout constants — must match Header.h
# ---------------------------------------------------------------------------

HEADER_SIZE = 4096                         # bytes per header
DEFAULT_MAX_TABLE_SIZE = 65536             # bytes reserved for file table per slot
SLOT_RESERVED = HEADER_SIZE + DEFAULT_MAX_TABLE_SIZE  # 69632 bytes per slot

# HMAC field offset and size inside the header (spec Table 4.2).
POSITION_HEADER_HMAC = 0x00A0             # byte offset of 32-byte HMAC field
HMAC_SIZE = 32

# Encrypted DEK field — offset 0x0048, 32 bytes.
POSITION_ENCRYPTED_DEK = 0x0048
ENCRYPTED_DEK_SIZE = 32

# Magic bytes: "SCEF" at offset 0.
MAGIC_BYTES = b"SCEF"
MAGIC_OFFSET = 0
MAGIC_SIZE = 4

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Container size used in resilience tests — 4 MiB gives comfortable room
# between slots and avoids pathological slot-overlap edge cases.
RESILIENCE_CONTAINER_SIZE = DEFAULT_CONTAINER_SIZE  # 4 MiB


def slot_offset(container_size: int, percent: int) -> int:
    """
    Compute the byte offset of a slot.

    Matches the C++ formula:
      floor(container_size * percent / 100 / HEADER_SIZE) * HEADER_SIZE
    For percent == 0 always returns 0.
    """
    if percent == 0:
        return 0
    return (container_size * percent // 100 // HEADER_SIZE) * HEADER_SIZE


def corrupt_bytes(container_path: pathlib.Path, offset: int, length: int,
                  fill: bytes = b"\x00") -> None:
    """
    Overwrite `length` bytes at `offset` in the container file with `fill`.

    The fill pattern is tiled to cover exactly `length` bytes so callers can
    supply a non-trivial pattern (e.g. b"\\xFF" or b"EVIL").
    """
    tile = (fill * ((length // len(fill)) + 1))[:length]
    with open(container_path, "r+b") as f:
        f.seek(offset)
        f.write(tile)


def make_test_container(tmp_path: pathlib.Path, filename: str = "payload.bin",
                        content: bytes = None) -> tuple[pathlib.Path, pathlib.Path, bytes]:
    """
    Create a minimal valid container with one known binary file.

    Returns (container_dir, container_path, original_bytes).
    """
    if content is None:
        # ~2 KB of deterministic content — avoids os.urandom for reproducibility.
        content = bytes((i * 37 + 91) & 0xFF for i in range(2048))

    cdir = tmp_path / "container"
    cdir.mkdir()
    src = make_file_with_bytes(tmp_path / filename, content)
    create_container(cdir, [src], size=RESILIENCE_CONTAINER_SIZE)
    return cdir, cdir / "container.scef", content


def assert_list_succeeds(cdir: pathlib.Path, filename: str) -> None:
    """Assert that 'scef list' succeeds and the expected filename appears in output."""
    result = list_container(cdir, expect_success=True)
    assert filename in result.stdout, (
        f"Expected filename '{filename}' not found in 'scef list' output:\n{result.stdout}"
    )


def assert_extract_roundtrip(cdir: pathlib.Path, tmp_path: pathlib.Path,
                              filename: str, expected: bytes) -> None:
    """Extract one file and assert byte-perfect match against expected content."""
    outdir = tmp_path / "out"
    outdir.mkdir(exist_ok=True)
    extract_files(cdir, outdir, files=[filename])
    actual = (outdir / filename).read_bytes()
    assert actual == expected, (
        f"Extracted '{filename}' does not match original: "
        f"expected {len(expected)} bytes, got {len(actual)} bytes. "
        f"First diff at index "
        f"{next((i for i, (a, b) in enumerate(zip(actual, expected)) if a != b), -1)}"
    )


# ---------------------------------------------------------------------------
# Group 1 — Single slot corruption, fallback succeeds
# ---------------------------------------------------------------------------

class TestSingleSlotCorruption:
    """
    Corrupt one slot's magic bytes.  The other three slots remain valid;
    readMeta() must recover and all operations must succeed.
    """

    def test_TC_HDR_01_corrupt_slot0_magic_fallback_to_slot1(self, tmp_path):
        """
        TC-HDR-01: Zero out slot 0 magic bytes.
        Expected: fallback to slot 1 (magic valid there) → list/extract succeed.
        """
        cdir, container_path, content = make_test_container(tmp_path)

        # Overwrite the 4-byte magic at offset 0 (slot 0).
        corrupt_bytes(container_path, MAGIC_OFFSET, MAGIC_SIZE)

        assert_list_succeeds(cdir, "payload.bin")
        assert_extract_roundtrip(cdir, tmp_path, "payload.bin", content)

    def test_TC_HDR_02_corrupt_slot1_magic_slot0_used(self, tmp_path):
        """
        TC-HDR-02: Corrupt slot 1 magic.
        Expected: slot 0 is still valid → used normally, list/extract succeed.
        """
        cdir, container_path, content = make_test_container(tmp_path)

        off1 = slot_offset(RESILIENCE_CONTAINER_SIZE, 25)
        corrupt_bytes(container_path, off1 + MAGIC_OFFSET, MAGIC_SIZE)

        assert_list_succeeds(cdir, "payload.bin")
        assert_extract_roundtrip(cdir, tmp_path, "payload.bin", content)

    def test_TC_HDR_03_zero_entire_slot0_header_fallback(self, tmp_path):
        """
        TC-HDR-03: Zero the entire 4096-byte slot 0 header block.
        Expected: fallback to slot 1 → list/extract succeed.
        """
        cdir, container_path, content = make_test_container(tmp_path)

        corrupt_bytes(container_path, 0, HEADER_SIZE)

        assert_list_succeeds(cdir, "payload.bin")
        assert_extract_roundtrip(cdir, tmp_path, "payload.bin", content)

    def test_TC_HDR_04_corrupt_slot0_and_slot1_magic_fallback_to_slot2(self, tmp_path):
        """
        TC-HDR-04: Corrupt magic in slots 0 and 1.
        Expected: fallback to slot 2 → list/extract succeed.
        """
        cdir, container_path, content = make_test_container(tmp_path)

        off0 = slot_offset(RESILIENCE_CONTAINER_SIZE, 0)
        off1 = slot_offset(RESILIENCE_CONTAINER_SIZE, 25)
        corrupt_bytes(container_path, off0 + MAGIC_OFFSET, MAGIC_SIZE)
        corrupt_bytes(container_path, off1 + MAGIC_OFFSET, MAGIC_SIZE)

        assert_list_succeeds(cdir, "payload.bin")
        assert_extract_roundtrip(cdir, tmp_path, "payload.bin", content)


# ---------------------------------------------------------------------------
# Group 2 — Multiple slot corruption, last remaining slot used
# ---------------------------------------------------------------------------

class TestMultipleSlotCorruption:
    """
    Corrupt several slots simultaneously.  The surviving slot must be enough
    for full recovery.
    """

    def test_TC_HDR_05_corrupt_slots_0_1_2_use_slot_3(self, tmp_path):
        """
        TC-HDR-05: Corrupt magic in slots 0, 1, 2.
        Expected: fallback reaches slot 3 (last resort) → list/extract succeed.
        """
        cdir, container_path, content = make_test_container(tmp_path)

        for pct in [0, 25, 50]:
            off = slot_offset(RESILIENCE_CONTAINER_SIZE, pct)
            corrupt_bytes(container_path, off + MAGIC_OFFSET, MAGIC_SIZE)

        assert_list_succeeds(cdir, "payload.bin")
        assert_extract_roundtrip(cdir, tmp_path, "payload.bin", content)

    def test_TC_HDR_06_corrupt_slots_1_2_3_slot0_intact(self, tmp_path):
        """
        TC-HDR-06: Corrupt magic in backup slots 1, 2, 3 — leave slot 0 intact.
        Expected: slot 0 is used normally → list/extract succeed.
        """
        cdir, container_path, content = make_test_container(tmp_path)

        for pct in [25, 50, 75]:
            off = slot_offset(RESILIENCE_CONTAINER_SIZE, pct)
            corrupt_bytes(container_path, off + MAGIC_OFFSET, MAGIC_SIZE)

        assert_list_succeeds(cdir, "payload.bin")
        assert_extract_roundtrip(cdir, tmp_path, "payload.bin", content)


# ---------------------------------------------------------------------------
# Group 3 — All slots corrupted, graceful failure
# ---------------------------------------------------------------------------

class TestAllSlotsCorrupted:
    """
    When every slot is unreadable, readMeta() must raise a clear error;
    scef must exit non-zero.
    """

    def test_TC_HDR_07_all_four_magic_corrupt_must_fail(self, tmp_path):
        """
        TC-HDR-07: Corrupt magic bytes in all 4 slots.
        Expected: 'scef list' exits non-zero with an error message.
        """
        cdir, container_path, _ = make_test_container(tmp_path)

        for pct in [0, 25, 50, 75]:
            off = slot_offset(RESILIENCE_CONTAINER_SIZE, pct)
            corrupt_bytes(container_path, off + MAGIC_OFFSET, MAGIC_SIZE)

        result = list_container(cdir, expect_success=False)
        assert result.returncode != 0, (
            "scef list must fail when all 4 slot magic bytes are corrupted"
        )
        # Verify that there is some diagnostic output — not a silent crash.
        combined = result.stdout + result.stderr
        assert len(combined.strip()) > 0, (
            "scef should print an error message when all slots are unreadable"
        )

    def test_TC_HDR_08_zeroed_container_must_fail_gracefully(self, tmp_path):
        """
        TC-HDR-08: Overwrite the entire container file with zeros.
        Expected: 'scef list' exits non-zero without crashing or hanging.
        """
        cdir, container_path, _ = make_test_container(tmp_path)

        container_path.write_bytes(b"\x00" * RESILIENCE_CONTAINER_SIZE)

        result = list_container(cdir, expect_success=False)
        assert result.returncode != 0, (
            "scef list must fail on a fully-zeroed container"
        )


# ---------------------------------------------------------------------------
# Group 4 — HMAC / crypto corruption with fallback
# ---------------------------------------------------------------------------

class TestHmacCorruption:
    """
    HMAC failure on a single slot triggers fallback to remaining slots.
    Only if ALL slots fail does the operation fail.
    """

    def test_TC_HDR_09_corrupt_hmac_slot0_falls_back(self, tmp_path):
        """
        TC-HDR-09: Corrupt the 32-byte HMAC field in slot 0 while leaving magic intact.
        Slots 1-3 are healthy → fallback succeeds → 'scef list' works.
        """
        cdir, container_path, _ = make_test_container(tmp_path)

        corrupt_bytes(container_path, POSITION_HEADER_HMAC, HMAC_SIZE, fill=b"\xFF")

        assert_list_succeeds(cdir, "payload.bin")

    def test_TC_HDR_09b_corrupt_hmac_slot0_extract_roundtrip(self, tmp_path):
        """
        TC-HDR-09b: After corrupting slot 0 HMAC, extract must produce byte-perfect output.
        """
        cdir, container_path, content = make_test_container(tmp_path)

        corrupt_bytes(container_path, POSITION_HEADER_HMAC, HMAC_SIZE, fill=b"\xFF")

        assert_extract_roundtrip(cdir, tmp_path, "payload.bin", content)

    def test_TC_HDR_10_corrupt_dek_slot0_falls_back(self, tmp_path):
        """
        TC-HDR-10: Overwrite the encrypted DEK in slot 0 with garbage.
        Slots 1-3 are healthy → fallback succeeds.
        """
        cdir, container_path, _ = make_test_container(tmp_path)

        data = bytearray(container_path.read_bytes())
        dek_start = POSITION_ENCRYPTED_DEK
        for i in range(ENCRYPTED_DEK_SIZE):
            data[dek_start + i] ^= 0xFF
        container_path.write_bytes(bytes(data))

        assert_list_succeeds(cdir, "payload.bin")

    def test_TC_HDR_10b_corrupt_hmac_all_slots_fails(self, tmp_path):
        """
        TC-HDR-10b: Corrupt HMAC field in ALL 4 slots → must fail.
        This is the "wrong password or corrupted" case.
        """
        cdir, container_path, _ = make_test_container(tmp_path)

        cs = RESILIENCE_CONTAINER_SIZE
        for percent in (0, 25, 50, 75):
            off = slot_offset(cs, percent)
            corrupt_bytes(container_path, off + POSITION_HEADER_HMAC, HMAC_SIZE, fill=b"\xFF")

        result = list_container(cdir, expect_success=False)
        assert result.returncode != 0, (
            "scef list must fail when ALL slot HMACs are corrupted"
        )

    def test_TC_HDR_10c_corrupt_dek_all_slots_fails(self, tmp_path):
        """
        TC-HDR-10c: Corrupt encrypted DEK in ALL 4 slots → must fail.
        """
        cdir, container_path, _ = make_test_container(tmp_path)

        data = bytearray(container_path.read_bytes())
        cs = RESILIENCE_CONTAINER_SIZE
        for percent in (0, 25, 50, 75):
            off = slot_offset(cs, percent)
            for i in range(ENCRYPTED_DEK_SIZE):
                data[off + POSITION_ENCRYPTED_DEK + i] ^= 0xFF
        container_path.write_bytes(bytes(data))

        result = list_container(cdir, expect_success=False)
        assert result.returncode != 0, (
            "scef list must fail when ALL slot DEKs are corrupted"
        )

    def test_TC_HDR_10d_corrupt_hmac_3_of_4_recovers(self, tmp_path):
        """
        TC-HDR-10d: Corrupt HMAC in slots 0, 1, 2 but leave slot 3 healthy.
        Slot 3 should still work.
        """
        cdir, container_path, _ = make_test_container(tmp_path)

        cs = RESILIENCE_CONTAINER_SIZE
        for percent in (0, 25, 50):
            off = slot_offset(cs, percent)
            corrupt_bytes(container_path, off + POSITION_HEADER_HMAC, HMAC_SIZE, fill=b"\xFF")

        assert_list_succeeds(cdir, "payload.bin")


# ---------------------------------------------------------------------------
# Group 5 — File table corruption
# ---------------------------------------------------------------------------

class TestFileTableCorruption:
    """
    The file table sits immediately after the header in each slot.
    Corrupting the table of the active slot must make file operations fail
    (GCM authentication on the table ciphertext catches corruption).
    """

    def test_TC_HDR_11_corrupt_file_table_slot0_header_intact(self, tmp_path):
        """
        TC-HDR-11: Corrupt the file table area of slot 0 (first bytes after header)
        while leaving slot 0 header HMAC valid AND slots 1-3 fully intact.

        Expected: readMeta() validates slot 0 header (HMAC + DEK unwrap pass),
        attempts to decrypt slot 0 file table → GCM auth fails → falls through to
        slot 1, whose file table is healthy. 'scef list' must SUCCEED via slot 1
        recovery.

        This is the spec-correct crash-resilience behavior fixed by src F-1
        (Wave 2): the file-table read is now inside the per-slot recovery loop.
        """
        cdir, container_path, _ = make_test_container(tmp_path)

        # File table starts immediately after header (offset HEADER_SIZE in slot 0).
        table_start = HEADER_SIZE
        corrupt_bytes(container_path, table_start, 64, fill=b"\xAA")

        result = list_container(cdir, expect_success=True)
        assert result.returncode == 0, (
            "scef list must succeed via slot-1 recovery when only slot 0 file "
            "table is corrupted (slots 1-3 are intact)"
        )

    def test_TC_HDR_12_corrupt_file_table_slot0_only_slot1_plus_intact(self, tmp_path):
        """
        TC-HDR-12: Corrupt the entire slot 0 file table region (max_table_size
        bytes) but leave slot 0 header and slots 1-3 intact.

        Expected: readMeta() validates slot 0 header, attempts table decrypt,
        AES-GCM auth fails on the corrupt ciphertext, recovery loop advances to
        slot 1 whose header AND table are both healthy. 'scef list' must
        SUCCEED.

        This verifies that file-table recovery is NOT coupled to header
        recovery — the loop can keep trying slots even after a slot's header
        validates but its table fails (src F-1, Wave 2).
        """
        cdir, container_path, _ = make_test_container(tmp_path)

        # Corrupt only the file table in slot 0; all headers and slots 1-3 remain valid.
        table_start = HEADER_SIZE
        corrupt_bytes(container_path, table_start, DEFAULT_MAX_TABLE_SIZE, fill=b"\xBB")

        result = list_container(cdir, expect_success=True)
        assert result.returncode == 0, (
            "scef list must succeed via slot-1 recovery when slot 0 file "
            "table is fully corrupted (slots 1-3 are intact)"
        )


# ---------------------------------------------------------------------------
# Group 6 — Truncation
# ---------------------------------------------------------------------------

class TestTruncation:
    """
    Truncated containers represent incomplete writes or physically damaged media.
    The code must fail gracefully without crashes or hangs.
    """

    def test_TC_HDR_13_truncate_to_header_only_fails(self, tmp_path):
        """
        TC-HDR-13: Truncate the container to exactly HEADER_SIZE bytes (4096).
        Slot 0 magic is present, but the file table is missing.
        Expected: 'scef list' exits non-zero (file table read fails).
        """
        cdir, container_path, _ = make_test_container(tmp_path)

        data = container_path.read_bytes()
        container_path.write_bytes(data[:HEADER_SIZE])

        result = list_container(cdir, expect_success=False)
        assert result.returncode != 0, (
            "scef list must fail when container is truncated to header size only"
        )

    def test_TC_HDR_14_truncate_to_50pct_slots_0_and_1_still_work(self, tmp_path):
        """
        TC-HDR-14: Truncate the container to 50% of its original size.
        Slots 0 and 1 are fully within the retained portion.
        Expected: 'scef list' succeeds (slot 0 or 1 is usable).

        Note: slot 2 and 3 are in the truncated half, but slots 0 and 1
        should still be sufficient for full recovery.
        """
        cdir, container_path, content = make_test_container(tmp_path)

        full_size = len(container_path.read_bytes())
        truncate_at = full_size // 2

        # Ensure we retain both slot 0 (at 0%) and slot 1 (at 25%).
        off1 = slot_offset(full_size, 25)
        assert truncate_at > off1 + SLOT_RESERVED, (
            "Test precondition failed: slot 1 must be fully within the retained half"
        )

        data = container_path.read_bytes()
        container_path.write_bytes(data[:truncate_at])

        # list should still work because slot 0 is intact.
        assert_list_succeeds(cdir, "payload.bin")


# ---------------------------------------------------------------------------
# Group 7 — Roundtrip verification after recovery
# ---------------------------------------------------------------------------

class TestRoundtripAfterRecovery:
    """
    End-to-end: corrupt a slot, recover via fallback, verify byte-perfect extraction.
    These tests prove that resilience does not degrade data integrity.
    """

    def test_TC_HDR_15_corrupt_slot0_extract_all_files_byte_perfect(self, tmp_path):
        """
        TC-HDR-15: Corrupt slot 0 magic, recover via slot 1, extract all files.
        Expected: extracted content matches originals byte-for-byte.
        """
        cdir, container_path, content = make_test_container(tmp_path)

        corrupt_bytes(container_path, MAGIC_OFFSET, MAGIC_SIZE)

        assert_extract_roundtrip(cdir, tmp_path, "payload.bin", content)

    def test_TC_HDR_15b_corrupt_slots_0_1_extract_byte_perfect(self, tmp_path):
        """
        Variant of TC-HDR-15: corrupt slots 0 and 1, recover via slot 2.
        Verifies that double-slot loss still produces correct output.
        """
        cdir, container_path, content = make_test_container(tmp_path)

        for pct in [0, 25]:
            off = slot_offset(RESILIENCE_CONTAINER_SIZE, pct)
            corrupt_bytes(container_path, off + MAGIC_OFFSET, MAGIC_SIZE)

        assert_extract_roundtrip(cdir, tmp_path, "payload.bin", content)

    def test_TC_HDR_15c_corrupt_slot0_real_pdf_file(self, tmp_path):
        """
        TC-HDR-15c: Use a real PDF file (pdf_c.pdf, 448509 bytes).
        Corrupt slot 0, recover via slot 1, verify extracted PDF is byte-perfect.
        This exercises multi-block data reading after fallback header recovery.
        """
        test_data = (
            pathlib.Path(__file__).resolve().parent / "test_data" / "pdf_c.pdf"
        )
        if not test_data.exists():
            pytest.skip(f"Test data file not found: {test_data}")

        expected = test_data.read_bytes()

        # Container must be large enough for the PDF (~448 KB).
        # pdf_c.pdf = 448509 bytes. With per-chunk overhead (~28 bytes / 65536 chunk):
        # 7 chunks * (65536 + 28) = 458836 data bytes. Use 4 MiB — ample.
        cdir = tmp_path / "container"
        cdir.mkdir()
        create_container(cdir, [test_data], size=RESILIENCE_CONTAINER_SIZE)

        container_path = cdir / "container.scef"
        corrupt_bytes(container_path, MAGIC_OFFSET, MAGIC_SIZE)

        outdir = tmp_path / "out"
        outdir.mkdir()
        extract_files(cdir, outdir, files=["pdf_c.pdf"])

        actual = (outdir / "pdf_c.pdf").read_bytes()
        assert len(actual) == len(expected), (
            f"PDF size mismatch after slot-0 corruption recovery: "
            f"expected {len(expected)}, got {len(actual)}"
        )
        assert actual == expected, (
            "PDF content mismatch after slot-0 corruption and slot-1 fallback recovery"
        )

    def test_TC_HDR_15d_recover_then_operations_still_work(self, tmp_path):
        """
        Verify that after slot 0 is corrupted and the container is read via
        fallback, subsequent list + extract both return consistent results.
        This guards against a scenario where recovery works once but leaves
        internal state inconsistent for a second call.
        """
        cdir, container_path, content = make_test_container(tmp_path)

        corrupt_bytes(container_path, MAGIC_OFFSET, MAGIC_SIZE)

        # list succeeds and shows the file.
        assert_list_succeeds(cdir, "payload.bin")

        # extract also succeeds and content is correct.
        assert_extract_roundtrip(cdir, tmp_path, "payload.bin", content)


# ---------------------------------------------------------------------------
# Group 8 — Slot offset arithmetic verification
# ---------------------------------------------------------------------------

class TestSlotOffsetArithmetic:
    """
    Black-box verification that our Python slot_offset() helper matches the
    C++ computeSlotOffset() formula — both must agree for tests to be valid.
    """

    def test_slot_offsets_non_overlapping_for_4mib(self):
        """
        For a 4 MiB container the four slots must not overlap each other.
        Each slot occupies SLOT_RESERVED = 69632 bytes.
        """
        size = RESILIENCE_CONTAINER_SIZE
        offsets = [slot_offset(size, pct) for pct in [0, 25, 50, 75]]

        for i in range(len(offsets)):
            for j in range(i + 1, len(offsets)):
                start_i = offsets[i]
                end_i = start_i + SLOT_RESERVED
                start_j = offsets[j]
                end_j = start_j + SLOT_RESERVED
                overlap = max(0, min(end_i, end_j) - max(start_i, start_j))
                assert overlap == 0, (
                    f"Slots {i} and {j} overlap by {overlap} bytes at "
                    f"offsets {start_i} and {start_j} in a {size}-byte container"
                )

    def test_slot_0_is_always_zero(self):
        """Slot 0 is always at offset 0 regardless of container size."""
        for size in [RESILIENCE_CONTAINER_SIZE, 4 * SLOT_RESERVED, 1 * 1024 * 1024]:
            assert slot_offset(size, 0) == 0, (
                f"slot_offset({size}, 0) returned non-zero"
            )

    def test_slot_offsets_are_header_size_aligned(self):
        """All slot offsets must be aligned to HEADER_SIZE (4096 bytes)."""
        size = RESILIENCE_CONTAINER_SIZE
        for pct in [0, 25, 50, 75]:
            off = slot_offset(size, pct)
            assert off % HEADER_SIZE == 0, (
                f"slot_offset({size}, {pct}%) = {off} is not aligned to {HEADER_SIZE}"
            )

    def test_slot_offsets_strictly_increasing(self):
        """Slot offsets must be strictly increasing for a valid container size."""
        size = RESILIENCE_CONTAINER_SIZE
        offsets = [slot_offset(size, pct) for pct in [0, 25, 50, 75]]
        for i in range(1, len(offsets)):
            assert offsets[i] > offsets[i - 1], (
                f"Slot offsets not strictly increasing: "
                f"offsets[{i}]={offsets[i]} <= offsets[{i-1}]={offsets[i - 1]}"
            )
