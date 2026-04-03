"""
test_capacity_overflow.py — Tests for container capacity enforcement.

Background
----------
Bug: creating a container with -s 300000 (300 KB) and then adding two real
files that together exceed 300 KB succeeds without error.  The implementation
writes encrypted data past the usable data zones, either past the container
boundary or into slot-reserved areas.  A subsequent 'scef extract' fails with
"Data block authentication failed" because the overwritten blocks are corrupt.

Expected behaviour (what the fix must achieve):
  - 'scef create' MUST fail at creation time with a non-zero exit code when
    the requested container size is too small to hold the encrypted form of
    the provided files.
  - The container file must not be left in a partially-written, corrupt state
    when create fails.
  - If the container is large enough, the full create -> list -> extract round-
    trip must succeed and produce byte-perfect output.

Real files used
---------------
The tests use two documents from docs/official/ to make the scenario concrete
and reproducible:

  Task_VKR_final.pdf  — 199219 bytes
  vkr_final.docx      — 108981 bytes
  Combined raw size   — 308200 bytes

After AES-256-GCM encryption (12-byte nonce + 16-byte auth tag per 65536-byte
block), the encrypted size of both files together is 308368 bytes.

Container capacity (how many bytes are available for data blocks) depends on
the slot layout: 4 × (Header 4096 B + FileTable 65536 B) = 278528 B of slot
overhead is subtracted, and slot positions at 0/25/50/75% of the container
further fragment usable space.

Key sizes:
  300000 B  container => 21472 B data capacity  (far too small)
  583680 B  container => 305152 B data capacity (3216 B short)
  587776 B  container => 309248 B data capacity (880 B surplus, just fits)
    8 MiB   container => 8110080 B data capacity (plenty of room)

Test matrix
-----------
  TC-CAP-01  300 KB container, both files (~308 KB) -> create MUST fail
  TC-CAP-02  Good-size container (8 MiB), both files -> full round-trip passes
  TC-CAP-03  Just-barely-fits container (587776 B)   -> full round-trip passes
  TC-CAP-04  Just-barely-too-small (583680 B)        -> create MUST fail
  TC-CAP-05  Single PDF only, too-small container    -> create MUST fail
  TC-CAP-06  Single PDF only, adequate container     -> round-trip passes
  TC-CAP-07  Container created with PDF only, then DOCX added (overflow on add)
             -> 'scef add' MUST fail with non-zero exit code
  TC-CAP-08  300 KB container create failure must not leave a corrupt container
             that silently passes 'scef list'
"""

import pathlib
import pytest

from conftest import (
    list_container,
    extract_files,
    run_scef,
)

# ---------------------------------------------------------------------------
# Paths to the real source files (absolute, as required by the project style)
# ---------------------------------------------------------------------------

_PROJECT_ROOT = pathlib.Path(__file__).resolve().parent.parent.parent.parent
_DOCS_OFFICIAL = _PROJECT_ROOT / "docs" / "official"

PDF_PATH  = _DOCS_OFFICIAL / "Task_VKR_final.pdf"
DOCX_PATH = _DOCS_OFFICIAL / "vkr_final.docx"

PDF_SIZE  = 199219   # bytes on disk
DOCX_SIZE = 108981   # bytes on disk


# ---------------------------------------------------------------------------
# Layout constants (must mirror Header.h / FileManager.h)
# ---------------------------------------------------------------------------

HEADER_SIZE           = 4096
DEFAULT_MAX_TABLE_SIZE = 65536    # one BLOCK_SIZE worth of file-table space
BLOCK_SIZE            = 65536
NONCE_SIZE            = 12
AUTH_TAG_SIZE         = 16
ENCRYPTED_BLOCK_SIZE  = BLOCK_SIZE + NONCE_SIZE + AUTH_TAG_SIZE  # 65564
SLOT_RESERVED         = HEADER_SIZE + DEFAULT_MAX_TABLE_SIZE     # 69632
MINIMAL_CONTAINER_SIZE = 4 * SLOT_RESERVED                       # 278528


# ---------------------------------------------------------------------------
# Derived capacity constants (validated by pre-test assertions below)
# ---------------------------------------------------------------------------

def _compute_slot_offset(container_size: int, percent: int) -> int:
    """Mirror of FileManager::compute_slot_offset() in FileManager.h."""
    if percent == 0:
        return 0
    return (container_size * percent // 100 // HEADER_SIZE) * HEADER_SIZE


def _data_capacity(container_size: int) -> int:
    """
    Total bytes available for encrypted data blocks in a container of
    *container_size* bytes, accounting for all four slot-reserved areas.
    """
    slots = [_compute_slot_offset(container_size, p) for p in (0, 25, 50, 75)]
    capacity = 0
    for i in range(4):
        zone_start = slots[i] + SLOT_RESERVED
        zone_end   = slots[i + 1] if i < 3 else container_size
        if zone_end > zone_start:
            capacity += zone_end - zone_start
    return capacity


def _encrypted_size(plain_bytes: int) -> int:
    """Encrypted on-disk size of *plain_bytes* of plaintext data."""
    full_blocks = plain_bytes // BLOCK_SIZE
    remainder   = plain_bytes % BLOCK_SIZE
    size = full_blocks * ENCRYPTED_BLOCK_SIZE
    if remainder:
        size += remainder + NONCE_SIZE + AUTH_TAG_SIZE
    return size


# Pre-computed constants used in every test.  Values are confirmed by the
# capacity calculations in the module docstring.
PDF_ENC_SIZE  = _encrypted_size(PDF_SIZE)    # 199331
DOCX_ENC_SIZE = _encrypted_size(DOCX_SIZE)   # 109037
BOTH_ENC_SIZE = PDF_ENC_SIZE + DOCX_ENC_SIZE # 308368

# Container sizes for each test scenario (see module docstring for derivation).
CONTAINER_FAR_TOO_SMALL      = 300000   # capacity  21472 — far too small
CONTAINER_ONE_BLOCK_TOO_SMALL = 583680  # capacity 305152 — 3216 B short
CONTAINER_JUST_FITS           = 587776  # capacity 309248 — 880 B surplus
CONTAINER_GOOD_SIZE           = 8 * 1024 * 1024  # capacity ~8 MB, plenty


# ---------------------------------------------------------------------------
# Module-level sanity checks: ensure the source files exist and the size
# constants match reality.  These run when pytest collects the module, before
# any test body executes.
# ---------------------------------------------------------------------------

def _verify_source_files_and_constants() -> None:
    assert PDF_PATH.exists(), (
        f"Required source file not found: {PDF_PATH}\n"
        f"Run tests from a full MEPHI_DIPLOMA checkout."
    )
    assert DOCX_PATH.exists(), (
        f"Required source file not found: {DOCX_PATH}\n"
        f"Run tests from a full MEPHI_DIPLOMA checkout."
    )

    actual_pdf_size  = PDF_PATH.stat().st_size
    actual_docx_size = DOCX_PATH.stat().st_size
    assert actual_pdf_size == PDF_SIZE, (
        f"Task_VKR_final.pdf size changed: expected {PDF_SIZE}, "
        f"got {actual_pdf_size}.  Update PDF_SIZE in this file."
    )
    assert actual_docx_size == DOCX_SIZE, (
        f"vkr_final.docx size changed: expected {DOCX_SIZE}, "
        f"got {actual_docx_size}.  Update DOCX_SIZE in this file."
    )

    # Confirm capacity arithmetic: the 'just fits' size must actually fit, and
    # the 'one block too small' size must actually not fit.
    assert _data_capacity(CONTAINER_JUST_FITS) >= BOTH_ENC_SIZE, (
        f"CONTAINER_JUST_FITS ({CONTAINER_JUST_FITS}) "
        f"has capacity {_data_capacity(CONTAINER_JUST_FITS)} "
        f"but needs {BOTH_ENC_SIZE}"
    )
    assert _data_capacity(CONTAINER_ONE_BLOCK_TOO_SMALL) < BOTH_ENC_SIZE, (
        f"CONTAINER_ONE_BLOCK_TOO_SMALL ({CONTAINER_ONE_BLOCK_TOO_SMALL}) "
        f"unexpectedly fits both files"
    )
    assert _data_capacity(CONTAINER_FAR_TOO_SMALL) < BOTH_ENC_SIZE, (
        f"CONTAINER_FAR_TOO_SMALL ({CONTAINER_FAR_TOO_SMALL}) "
        f"unexpectedly fits both files"
    )
    assert _data_capacity(CONTAINER_GOOD_SIZE) >= BOTH_ENC_SIZE, (
        f"CONTAINER_GOOD_SIZE ({CONTAINER_GOOD_SIZE}) is unexpectedly too small"
    )


_verify_source_files_and_constants()


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _assert_files_byte_equal(original: pathlib.Path, extracted: pathlib.Path) -> None:
    """Assert that *extracted* is byte-for-byte identical to *original*."""
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
        f"{extracted.name}: content mismatch — "
        f"first differing byte at index "
        f"{next(i for i,(a,b) in enumerate(zip(extr_data, orig_data)) if a != b)}"
    )


# ---------------------------------------------------------------------------
# TC-CAP-01
# Container clearly too small for both files.
#
# BUG: currently 'scef create' exits 0 here (silent corruption).
# EXPECTED: non-zero exit code at create time.
# ---------------------------------------------------------------------------

class TestCreateOverflowFarTooSmall:
    """TC-CAP-01: 300 KB container, two files totaling ~308 KB — must fail."""

    def test_create_fails_when_files_exceed_capacity(self, tmp_path):
        """
        Creating a container with -s 300000 and adding both PDF (199219 B) and
        DOCX (108981 B) must fail.

        The total encrypted size (308368 B) exceeds the container's data
        capacity (21472 B).  The implementation must detect this before or
        during the write phase and exit with a non-zero return code.

        This test is expected to FAIL against the current (buggy) code.
        It will PASS once the fix is in place.
        """
        cdir = tmp_path / "c"
        cdir.mkdir()

        result = run_scef(
            [
                "create",
                "-c", str(cdir),
                "-f", str(PDF_PATH),
                "-f", str(DOCX_PATH),
                "-s", str(CONTAINER_FAR_TOO_SMALL),
            ],
            expect_success=False,
        )

        assert result.returncode != 0, (
            f"'scef create -s {CONTAINER_FAR_TOO_SMALL}' with files totaling "
            f"{PDF_SIZE + DOCX_SIZE} raw bytes ({BOTH_ENC_SIZE} encrypted) "
            f"must exit non-zero — the files do not fit.\n"
            f"Container data capacity: {_data_capacity(CONTAINER_FAR_TOO_SMALL)} bytes.\n"
            f"Current behaviour (BUG): exits 0 and silently overwrites data.\n"
            f"stderr: {result.stderr.strip()}\n"
            f"stdout: {result.stdout.strip()}"
        )

    def test_create_error_output_is_not_empty(self, tmp_path):
        """
        When capacity is exceeded, the binary must emit a diagnostic message
        on stderr or stdout so the user knows what went wrong.
        """
        cdir = tmp_path / "c"
        cdir.mkdir()

        result = run_scef(
            [
                "create",
                "-c", str(cdir),
                "-f", str(PDF_PATH),
                "-f", str(DOCX_PATH),
                "-s", str(CONTAINER_FAR_TOO_SMALL),
            ],
            expect_success=False,
        )

        combined_output = result.stderr.strip() + result.stdout.strip()
        assert len(combined_output) > 0, (
            "Failed 'scef create' (capacity exceeded) produced no diagnostic output. "
            "The user needs to know why the operation failed."
        )


# ---------------------------------------------------------------------------
# TC-CAP-02
# Good-size container (8 MiB) — full round-trip must succeed.
#
# This establishes a baseline: if the container IS large enough, the
# complete create -> list -> extract pipeline must work for both real files.
# ---------------------------------------------------------------------------

class TestRoundtripGoodSize:
    """TC-CAP-02: 8 MiB container, both real files — full round-trip."""

    def test_create_succeeds_with_adequate_size(self, tmp_path):
        """'scef create' must exit 0 when the container is large enough."""
        cdir = tmp_path / "c"
        cdir.mkdir()

        result = run_scef(
            [
                "create",
                "-c", str(cdir),
                "-f", str(PDF_PATH),
                "-f", str(DOCX_PATH),
                "-s", str(CONTAINER_GOOD_SIZE),
            ],
            expect_success=False,
        )

        assert result.returncode == 0, (
            f"'scef create -s {CONTAINER_GOOD_SIZE}' with two files "
            f"({BOTH_ENC_SIZE} encrypted bytes, capacity "
            f"{_data_capacity(CONTAINER_GOOD_SIZE)} bytes) must succeed.\n"
            f"stderr: {result.stderr.strip()}"
        )

    def test_list_shows_both_files_after_create(self, tmp_path):
        """'scef list' must report both files after successful creation."""
        cdir = tmp_path / "c"
        cdir.mkdir()

        run_scef(
            [
                "create",
                "-c", str(cdir),
                "-f", str(PDF_PATH),
                "-f", str(DOCX_PATH),
                "-s", str(CONTAINER_GOOD_SIZE),
            ],
            expect_success=True,
        )

        list_result = list_container(cdir)
        assert "Task_VKR_final.pdf" in list_result.stdout, (
            "'scef list' output does not mention 'Task_VKR_final.pdf'"
        )
        assert "vkr_final.docx" in list_result.stdout, (
            "'scef list' output does not mention 'vkr_final.docx'"
        )

    def test_extract_pdf_is_byte_perfect(self, tmp_path):
        """Extracted PDF must be byte-for-byte identical to the original."""
        cdir = tmp_path / "c"
        cdir.mkdir()
        outdir = tmp_path / "out"
        outdir.mkdir()

        run_scef(
            [
                "create",
                "-c", str(cdir),
                "-f", str(PDF_PATH),
                "-f", str(DOCX_PATH),
                "-s", str(CONTAINER_GOOD_SIZE),
            ],
            expect_success=True,
        )

        extract_files(cdir, outdir, files=["Task_VKR_final.pdf"])

        _assert_files_byte_equal(PDF_PATH, outdir / "Task_VKR_final.pdf")

    def test_extract_docx_is_byte_perfect(self, tmp_path):
        """Extracted DOCX must be byte-for-byte identical to the original."""
        cdir = tmp_path / "c"
        cdir.mkdir()
        outdir = tmp_path / "out"
        outdir.mkdir()

        run_scef(
            [
                "create",
                "-c", str(cdir),
                "-f", str(PDF_PATH),
                "-f", str(DOCX_PATH),
                "-s", str(CONTAINER_GOOD_SIZE),
            ],
            expect_success=True,
        )

        extract_files(cdir, outdir, files=["vkr_final.docx"])

        _assert_files_byte_equal(DOCX_PATH, outdir / "vkr_final.docx")

    def test_extract_all_files_byte_perfect(self, tmp_path):
        """Extracting all files at once: both must be byte-perfect."""
        cdir = tmp_path / "c"
        cdir.mkdir()
        outdir = tmp_path / "out"
        outdir.mkdir()

        run_scef(
            [
                "create",
                "-c", str(cdir),
                "-f", str(PDF_PATH),
                "-f", str(DOCX_PATH),
                "-s", str(CONTAINER_GOOD_SIZE),
            ],
            expect_success=True,
        )

        extract_files(cdir, outdir)  # extract all

        _assert_files_byte_equal(PDF_PATH,  outdir / "Task_VKR_final.pdf")
        _assert_files_byte_equal(DOCX_PATH, outdir / "vkr_final.docx")


# ---------------------------------------------------------------------------
# TC-CAP-03
# Just-barely-fits container (587776 B) — full round-trip must succeed.
#
# This is a boundary test: the container has only 880 bytes of headroom beyond
# what the two encrypted files need.  A correct implementation must handle
# this without overflow.
# ---------------------------------------------------------------------------

class TestRoundtripJustFits:
    """TC-CAP-03: Minimum container that fits both files — round-trip must pass."""

    def test_create_succeeds_at_minimum_fitting_size(self, tmp_path):
        """
        'scef create' with container size = 587776 (880 B surplus after both
        files) must exit 0.
        """
        cdir = tmp_path / "c"
        cdir.mkdir()

        result = run_scef(
            [
                "create",
                "-c", str(cdir),
                "-f", str(PDF_PATH),
                "-f", str(DOCX_PATH),
                "-s", str(CONTAINER_JUST_FITS),
            ],
            expect_success=False,
        )

        assert result.returncode == 0, (
            f"'scef create -s {CONTAINER_JUST_FITS}' must succeed — "
            f"data capacity {_data_capacity(CONTAINER_JUST_FITS)} B >= "
            f"{BOTH_ENC_SIZE} B needed.\n"
            f"stderr: {result.stderr.strip()}"
        )

    def test_extract_all_byte_perfect_at_minimum_fitting_size(self, tmp_path):
        """
        After creating at the minimum fitting size, both files must extract
        byte-for-byte correctly.  A capacity overrun would corrupt the auth
        tags and cause 'Data block authentication failed' on extract.
        """
        cdir = tmp_path / "c"
        cdir.mkdir()
        outdir = tmp_path / "out"
        outdir.mkdir()

        run_scef(
            [
                "create",
                "-c", str(cdir),
                "-f", str(PDF_PATH),
                "-f", str(DOCX_PATH),
                "-s", str(CONTAINER_JUST_FITS),
            ],
            expect_success=True,
        )

        extract_files(cdir, outdir)

        _assert_files_byte_equal(PDF_PATH,  outdir / "Task_VKR_final.pdf")
        _assert_files_byte_equal(DOCX_PATH, outdir / "vkr_final.docx")


# ---------------------------------------------------------------------------
# TC-CAP-04
# Just-barely-too-small container (583680 B) — create must fail.
#
# This container has 3216 B less capacity than the two encrypted files need.
# It is exactly 4096 B (one alignment unit) below the minimum fitting size.
# ---------------------------------------------------------------------------

class TestCreateOverflowJustTooSmall:
    """TC-CAP-04: Container 4096 B below minimum fitting size — must fail."""

    def test_create_fails_when_4096_bytes_short(self, tmp_path):
        """
        'scef create -s 583680' with both real files must exit non-zero.

        Container data capacity: 305152 B.
        Encrypted data required: 308368 B.
        Deficit: 3216 B.

        This test is expected to FAIL against the current (buggy) code.
        """
        cdir = tmp_path / "c"
        cdir.mkdir()

        result = run_scef(
            [
                "create",
                "-c", str(cdir),
                "-f", str(PDF_PATH),
                "-f", str(DOCX_PATH),
                "-s", str(CONTAINER_ONE_BLOCK_TOO_SMALL),
            ],
            expect_success=False,
        )

        assert result.returncode != 0, (
            f"'scef create -s {CONTAINER_ONE_BLOCK_TOO_SMALL}' with both files "
            f"must fail — capacity {_data_capacity(CONTAINER_ONE_BLOCK_TOO_SMALL)} B "
            f"< {BOTH_ENC_SIZE} B needed (deficit "
            f"{BOTH_ENC_SIZE - _data_capacity(CONTAINER_ONE_BLOCK_TOO_SMALL)} B).\n"
            f"This is 4096 B (one alignment unit) below the minimum fitting size.\n"
            f"Current behaviour (BUG): exits 0 and silently corrupts the container.\n"
            f"stderr: {result.stderr.strip()}"
        )


# ---------------------------------------------------------------------------
# TC-CAP-05
# Single PDF only, too-small container.
#
# Isolates the per-file overflow: even a single file must be rejected when it
# does not fit.  Uses a container that holds the structural minimum but not
# the encrypted PDF.
# ---------------------------------------------------------------------------

class TestCreateOverflowSingleFile:
    """TC-CAP-05: Container too small for the PDF alone — must fail."""

    def test_create_fails_for_single_large_file_too_small_container(self, tmp_path):
        """
        The structural minimum (278528 B) has zero data capacity (all bytes
        consumed by four slot-reserved areas).  Creating a container of
        exactly 278528 B with the 199219 B PDF must therefore fail.

        This test is expected to FAIL against the current (buggy) code.
        """
        cdir = tmp_path / "c"
        cdir.mkdir()

        result = run_scef(
            [
                "create",
                "-c", str(cdir),
                "-f", str(PDF_PATH),
                "-s", str(MINIMAL_CONTAINER_SIZE),
            ],
            expect_success=False,
        )

        assert result.returncode != 0, (
            f"'scef create -s {MINIMAL_CONTAINER_SIZE}' (structural minimum) "
            f"with a {PDF_SIZE}-byte file must fail — "
            f"data capacity is "
            f"{_data_capacity(MINIMAL_CONTAINER_SIZE)} B, "
            f"encrypted PDF needs {PDF_ENC_SIZE} B.\n"
            f"Current behaviour (BUG): exits 0 and silently corrupts the container.\n"
            f"stderr: {result.stderr.strip()}"
        )


# ---------------------------------------------------------------------------
# TC-CAP-06
# Single PDF only, adequate container.
#
# Establishes that a single large file round-trips correctly when the
# container is large enough.  Smallest size that fits the PDF alone is
# 479232 B (capacity 200704 B >= 199331 B needed).
# ---------------------------------------------------------------------------

# Smallest container that fits the PDF alone.
_PDF_ONLY_MIN_SIZE = 479232   # capacity 200704 >= pdf_enc 199331


class TestRoundtripSingleLargeFile:
    """TC-CAP-06: Container sized for PDF only — round-trip must pass."""

    def test_create_with_single_pdf_succeeds(self, tmp_path):
        cdir = tmp_path / "c"
        cdir.mkdir()

        result = run_scef(
            [
                "create",
                "-c", str(cdir),
                "-f", str(PDF_PATH),
                "-s", str(_PDF_ONLY_MIN_SIZE),
            ],
            expect_success=False,
        )

        assert result.returncode == 0, (
            f"'scef create -s {_PDF_ONLY_MIN_SIZE}' with PDF ({PDF_SIZE} B) must succeed.\n"
            f"Container capacity: {_data_capacity(_PDF_ONLY_MIN_SIZE)} B, "
            f"PDF encrypted: {PDF_ENC_SIZE} B.\n"
            f"stderr: {result.stderr.strip()}"
        )

    def test_extract_pdf_byte_perfect_single_file_container(self, tmp_path):
        """PDF extracted from a tight container must be byte-perfect."""
        cdir = tmp_path / "c"
        cdir.mkdir()
        outdir = tmp_path / "out"
        outdir.mkdir()

        run_scef(
            [
                "create",
                "-c", str(cdir),
                "-f", str(PDF_PATH),
                "-s", str(_PDF_ONLY_MIN_SIZE),
            ],
            expect_success=True,
        )

        extract_files(cdir, outdir, files=["Task_VKR_final.pdf"])

        _assert_files_byte_equal(PDF_PATH, outdir / "Task_VKR_final.pdf")


# ---------------------------------------------------------------------------
# TC-CAP-07
# Overflow on 'scef add': container was created with the PDF only, then DOCX
# is added — but there is no room left.
#
# Uses _PDF_ONLY_MIN_SIZE so the PDF fits with only a small surplus.  The
# surplus (200704 - 199331 = 1373 B) is not enough for the encrypted DOCX
# (109037 B), so 'scef add' must reject the operation.
# ---------------------------------------------------------------------------

class TestAddOverflow:
    """TC-CAP-07: 'scef add' must fail when there is no room for the new file."""

    def test_add_fails_when_container_is_full(self, tmp_path):
        """
        1. Create a container just large enough for the PDF.
        2. Try to 'scef add' the DOCX — this must fail because the encrypted
           DOCX (109037 B) does not fit in the 1373 B of remaining space.

        The failure must be detected at add time, not silently overwrite data
        and then cause authentication errors on extract.

        This test is expected to FAIL against the current (buggy) code.
        """
        cdir = tmp_path / "c"
        cdir.mkdir()

        # Step 1: create with PDF only — this must succeed.
        run_scef(
            [
                "create",
                "-c", str(cdir),
                "-f", str(PDF_PATH),
                "-s", str(_PDF_ONLY_MIN_SIZE),
            ],
            expect_success=True,
        )

        # Step 2: add DOCX — must fail (no room).
        result = run_scef(
            [
                "add",
                "-c", str(cdir),
                "-f", str(DOCX_PATH),
            ],
            expect_success=False,
        )

        assert result.returncode != 0, (
            f"'scef add' of {DOCX_SIZE}-byte DOCX into a container with "
            f"only ~1373 B of remaining space must fail.\n"
            f"Remaining capacity after PDF: "
            f"{_data_capacity(_PDF_ONLY_MIN_SIZE) - PDF_ENC_SIZE} B, "
            f"DOCX encrypted: {DOCX_ENC_SIZE} B.\n"
            f"Current behaviour (BUG): exits 0 and silently corrupts the container.\n"
            f"stderr: {result.stderr.strip()}"
        )

    def test_add_overflow_does_not_corrupt_original_file(self, tmp_path):
        """
        After a failed 'scef add', the originally stored PDF must still be
        extractable and byte-perfect.

        This guards against the current bug where a failed add leaves the
        container in a state that causes 'Data block authentication failed'
        on any subsequent extract, even for files written before the overflow.
        """
        cdir = tmp_path / "c"
        cdir.mkdir()
        outdir = tmp_path / "out"
        outdir.mkdir()

        # Create with PDF only.
        run_scef(
            [
                "create",
                "-c", str(cdir),
                "-f", str(PDF_PATH),
                "-s", str(_PDF_ONLY_MIN_SIZE),
            ],
            expect_success=True,
        )

        # Attempt the overflowing add (we expect this to fail, but do not
        # assert the return code here — we care only about the aftermath).
        run_scef(
            [
                "add",
                "-c", str(cdir),
                "-f", str(DOCX_PATH),
            ],
            expect_success=False,
        )

        # After the failed add, the original PDF must still be intact.
        extract_result = extract_files(
            cdir,
            outdir,
            files=["Task_VKR_final.pdf"],
            expect_success=False,
        )

        if extract_result.returncode == 0:
            # Extract succeeded — verify the content is still correct.
            _assert_files_byte_equal(PDF_PATH, outdir / "Task_VKR_final.pdf")
        else:
            # Extract failed entirely — this is the current bug: the container
            # was corrupted by the overflowing add.
            pytest.fail(
                "After a failed 'scef add', 'scef extract' of the originally "
                "stored PDF also fails.  The overflowing add corrupted the "
                "container.\n"
                f"extract stderr: {extract_result.stderr.strip()}"
            )


# ---------------------------------------------------------------------------
# TC-CAP-08
# After a failed create (container too small), the on-disk state must not
# allow 'scef list' to succeed — a corrupt partial container must not be
# treated as a valid, readable container.
# ---------------------------------------------------------------------------

class TestFailedCreateLeavesSafeState:
    """TC-CAP-08: A failed 'scef create' must not produce a corrupt but listable container."""

    def test_failed_create_does_not_leave_valid_container(self, tmp_path):
        """
        If 'scef create' fails due to capacity overflow, any resulting
        container.scef on disk must not be readable.  'scef list' on it must
        either (a) find no container.scef at all, or (b) exit non-zero when
        trying to read the incomplete/corrupt file.

        This prevents the confusion of a container that appears to exist
        (non-zero file size, SCEF magic present) but actually contains
        corrupt data blocks that will fail authentication on extract.
        """
        cdir = tmp_path / "c"
        cdir.mkdir()

        # Attempt the overflowing create.
        create_result = run_scef(
            [
                "create",
                "-c", str(cdir),
                "-f", str(PDF_PATH),
                "-f", str(DOCX_PATH),
                "-s", str(CONTAINER_FAR_TOO_SMALL),
            ],
            expect_success=False,
        )

        container_path = cdir / "container.scef"

        if not container_path.exists():
            # Best outcome: no container file created at all.
            return

        # If a container file was left on disk, it must not be listable with
        # the correct password — doing so would mean the binary accepts a
        # corrupt container as valid and sets up the user for a silent data
        # loss when they later run extract.
        list_result = run_scef(
            ["list", "-c", str(cdir)],
            expect_success=False,
        )

        assert list_result.returncode != 0, (
            "After a failed 'scef create' (capacity overflow), the leftover "
            "container.scef must NOT be listable.  The file is corrupt because "
            "data was written past the container boundary or into slot areas.\n"
            f"container.scef size on disk: {container_path.stat().st_size} bytes.\n"
            "A listable but corrupt container will cause 'Data block "
            "authentication failed' on extract — this is the original bug."
        )
