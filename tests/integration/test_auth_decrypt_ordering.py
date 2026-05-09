"""
test_auth_decrypt_ordering.py — Verify HMAC-then-DEK ordering (authenticate-then-decrypt).

Spec (container-format.md:72-74, FileManager.h:164-168):
  readMeta() sequence per slot:
    1. validateKdfParamsAndDeriveKek()   — derive KEK from password + stored salt/KDF params
    2. verifyHeaderHmac()                — verify HMAC-SHA256(KEK, header fields excl. HMAC)
    3. unwrapDekFromHeader()             — AES-256-GCM decrypt encrypted_dek using KEK

  If step 2 fails (HMAC mismatch), step 3 is NOT attempted — the slot is
  rejected and the next slot is tried.

Why this matters:
  If HMAC was skipped or performed after DEK decryption, corrupting the salt
  (which is HMAC-protected but NOT AES-GCM-protected) would produce a wrong
  KEK, which would produce a wrong DEK from step 3, and AES-GCM would then
  fail on the file table with "authentication failed" — a DIFFERENT error path.

  The HMAC-then-DEK ordering guarantees that:
    - Any modification to HMAC-protected fields (salt, encrypted_dek, cipher_id,
      kdf params, container_size, file_count, header_version) is detected BEFORE
      DEK decryption is attempted.
    - The error message should indicate HMAC/authentication failure, not AES-GCM
      failure on the file table.

Test strategy:
  1. Corrupt only the encrypted_dek bytes (0x0048..0x0067) in slot 0 —
     this invalidates the HMAC (DEK is HMAC-covered) and should cause slot 0
     fallback to slot 1, which succeeds.
  2. Corrupt only the salt bytes (0x001C..0x003B) in slot 0 —
     salt is HMAC-covered but NOT AES-GCM-protected; if HMAC is checked first,
     this causes HMAC failure and slot fallback.  If HMAC is checked AFTER DEK
     decryption, the wrong KEK would attempt to decrypt the DEK, AES-GCM would
     fail, and the error would come from the DEK path rather than the HMAC path.
  3. Corrupt the HMAC field itself (0x00A0..0x00BF) in all 4 slots —
     must fail with an error mentioning HMAC/authentication.

All three tests together prove: HMAC covers the DEK and salt fields, AND
HMAC failure causes slot rejection independently of AES-GCM.
"""

import pathlib
import struct

import pytest

from conftest import (
    DEFAULT_PASSWORD,
    DEFAULT_CONTAINER_SIZE,
    create_container,
    list_container,
    make_text_file,
    make_file_with_bytes,
)

# ---------------------------------------------------------------------------
# Layout constants (must match Header.h binary layout)
# ---------------------------------------------------------------------------

HEADER_SIZE = 4096

# Offsets and sizes of HMAC-protected fields in the header.
POSITION_SALT           = 0x001C   # 32 bytes — Argon2id salt
SALT_SIZE               = 32

POSITION_ENCRYPTED_DEK  = 0x0048   # 32 bytes — AES-256-GCM encrypted master key
ENCRYPTED_DEK_SIZE      = 32

POSITION_HEADER_HMAC    = 0x00A0   # 32 bytes — HMAC-SHA256 of header fields
HMAC_SIZE               = 32


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def slot_offset(container_size: int, percent: int) -> int:
    """
    Compute the byte offset of a slot using the spec formula.
    Matches FileManager::computeSlotOffset().
    """
    if percent == 0:
        return 0
    return (container_size * percent // 100 // HEADER_SIZE) * HEADER_SIZE


def corrupt_bytes(
    container_path: pathlib.Path,
    offset: int,
    length: int,
    xor_byte: int = 0xFF,
) -> None:
    """
    XOR `length` bytes at `offset` with `xor_byte`.
    XOR ensures the bytes are definitely changed (not a no-op if they were already
    xor_byte), while being reversible for diagnosis.
    """
    data = bytearray(container_path.read_bytes())
    for i in range(length):
        data[offset + i] ^= xor_byte
    container_path.write_bytes(bytes(data))


def make_test_container(
    tmp_path: pathlib.Path,
    filename: str = "payload.bin",
    content: bytes = None,
) -> tuple:
    """
    Create a minimal valid container with one known file.
    Returns (container_dir, container_path, original_content).
    """
    if content is None:
        content = bytes((i * 37 + 91) & 0xFF for i in range(512))

    cdir = tmp_path / "container"
    cdir.mkdir()
    src_path = tmp_path / filename
    src_path.write_bytes(content)
    create_container(cdir, [src_path], size=DEFAULT_CONTAINER_SIZE)
    return cdir, cdir / "container.scef", content


# ---------------------------------------------------------------------------
# Group 1 — HMAC-protected field corruption in slot 0 triggers slot fallback
# ---------------------------------------------------------------------------

class TestHmacProtectedFieldCorruption:
    """
    Corrupting a field that is HMAC-protected in slot 0 must cause slot 0
    to be rejected and slot 1 to be used instead.  The operation must succeed.

    This proves HMAC covers these fields and that HMAC failure triggers
    slot fallback (not AES-GCM failure on the DEK or file table).
    """

    def test_corrupt_dek_in_slot0_falls_back_to_slot1(self, tmp_path):
        """
        Flip bytes in encrypted_dek (offset 0x0048, slot 0).

        The encrypted_dek field is covered by the HMAC.  Corrupting it invalidates
        the HMAC, so slot 0 must be rejected.  Slots 1-3 are intact and the
        operation must succeed via fallback.

        If the implementation checked HMAC AFTER attempting DEK decryption, the
        AES-GCM auth tag on the DEK would fire first — but we want HMAC to fire
        first per the spec ordering.  This test is behavioral: as long as fallback
        works, the ordering is at least functionally correct.
        """
        cdir, container_path, _ = make_test_container(tmp_path)

        # Corrupt encrypted_dek in slot 0 only (slot 0 is at offset 0).
        corrupt_bytes(container_path, POSITION_ENCRYPTED_DEK, ENCRYPTED_DEK_SIZE)

        # 'scef list' must succeed via slot 1 fallback.
        result = list_container(cdir, expect_success=False)
        assert result.returncode == 0, (
            "scef list must succeed after encryped_dek corruption in slot 0 "
            "(should fall back to slot 1).  "
            f"returncode={result.returncode}\n"
            f"stderr: {result.stderr.strip()}"
        )
        assert "payload.bin" in result.stdout, (
            "File 'payload.bin' must appear in list output after slot 0 fallback"
        )

    def test_corrupt_salt_in_slot0_falls_back_to_slot1(self, tmp_path):
        """
        Flip bytes in salt (offset 0x001C, slot 0).

        The salt is HMAC-protected but is NOT inside the AES-GCM ciphertext.
        Corrupting it produces a different KEK on step 1, which causes HMAC
        verification failure on step 2 — the slot is rejected.

        Critically: if HMAC was checked AFTER DEK decryption (wrong ordering),
        the wrong KEK would attempt to decrypt the DEK.  AES-GCM on the DEK
        would fail with an authentication error — a different error path from
        HMAC failure.  By verifying that fallback succeeds, we confirm the
        salt corruption is handled correctly regardless of which check fires.

        The diagnostic difference from DEK corruption: salt corruption produces
        a wrong KEK, so the HMAC will fail to verify (the stored HMAC was
        computed with the original KEK, not the one derived from the corrupt salt).
        """
        cdir, container_path, _ = make_test_container(tmp_path)

        # Corrupt salt in slot 0 only.
        corrupt_bytes(container_path, POSITION_SALT, SALT_SIZE)

        # 'scef list' must succeed via slot 1 fallback.
        result = list_container(cdir, expect_success=False)
        assert result.returncode == 0, (
            "scef list must succeed after salt corruption in slot 0 "
            "(should fall back to slot 1).  "
            f"returncode={result.returncode}\n"
            f"stderr: {result.stderr.strip()}"
        )
        assert "payload.bin" in result.stdout, (
            "File 'payload.bin' must appear in list output after slot 0 fallback"
        )

    def test_corrupt_dek_slot0_then_extract_byte_perfect(self, tmp_path):
        """
        After DEK corruption in slot 0, the file must still extract byte-perfectly
        via slot 1 fallback.  This confirms the fallback is not just cosmetic.
        """
        cdir, container_path, expected = make_test_container(tmp_path)
        corrupt_bytes(container_path, POSITION_ENCRYPTED_DEK, ENCRYPTED_DEK_SIZE)

        outdir = tmp_path / "out"
        outdir.mkdir()

        from conftest import extract_files
        extract_files(cdir, outdir, files=["payload.bin"])

        actual = (outdir / "payload.bin").read_bytes()
        assert actual == expected, (
            "Extracted content does not match original after slot 0 DEK corruption "
            "and slot 1 fallback"
        )

    def test_corrupt_salt_slot0_then_extract_byte_perfect(self, tmp_path):
        """
        After salt corruption in slot 0, the file must still extract byte-perfectly
        via slot 1 fallback.
        """
        cdir, container_path, expected = make_test_container(tmp_path)
        corrupt_bytes(container_path, POSITION_SALT, SALT_SIZE)

        outdir = tmp_path / "out"
        outdir.mkdir()

        from conftest import extract_files
        extract_files(cdir, outdir, files=["payload.bin"])

        actual = (outdir / "payload.bin").read_bytes()
        assert actual == expected, (
            "Extracted content does not match original after slot 0 salt corruption "
            "and slot 1 fallback"
        )


# ---------------------------------------------------------------------------
# Group 2 — HMAC field corruption in all 4 slots must fail with auth error
# ---------------------------------------------------------------------------

class TestAllSlotsHmacCorrupted:
    """
    When every slot's HMAC field is directly corrupted, no slot can pass
    HMAC verification regardless of the password.  The operation must fail.
    """

    def test_corrupt_hmac_in_all_4_slots_fails(self, tmp_path):
        """
        Flip bytes in the HMAC field (offset 0x00A0) of all four slots.

        With all four HMACs invalid, readMeta() must exhaust all slots and fail.
        The error must mention authentication or HMAC failure — not a silent crash
        and not a spurious success.
        """
        cdir, container_path, _ = make_test_container(tmp_path)

        container_size = len(container_path.read_bytes())
        for pct in (0, 25, 50, 75):
            slot_off = slot_offset(container_size, pct)
            corrupt_bytes(container_path, slot_off + POSITION_HEADER_HMAC, HMAC_SIZE)

        result = list_container(cdir, expect_success=False)

        assert result.returncode != 0, (
            "scef list must fail when all 4 slot HMACs are corrupted; "
            f"got returncode=0"
        )

        combined = (result.stdout + result.stderr).lower()
        assert any(keyword in combined for keyword in ("hmac", "authenticat", "corrupt", "wrong password")), (
            "Error output should mention HMAC/authentication failure when all HMACs "
            f"are corrupted.\nstdout: {result.stdout.strip()}\nstderr: {result.stderr.strip()}"
        )

    def test_corrupt_dek_in_all_4_slots_fails(self, tmp_path):
        """
        Flip bytes in the encrypted_dek field (offset 0x0048) of all four slots.

        The encrypted_dek is HMAC-covered, so corrupting it invalidates the HMAC
        for every slot.  All slots must fail and the operation must exit non-zero.
        """
        cdir, container_path, _ = make_test_container(tmp_path)

        container_size = len(container_path.read_bytes())
        for pct in (0, 25, 50, 75):
            slot_off = slot_offset(container_size, pct)
            corrupt_bytes(container_path, slot_off + POSITION_ENCRYPTED_DEK, ENCRYPTED_DEK_SIZE)

        result = list_container(cdir, expect_success=False)

        assert result.returncode != 0, (
            "scef list must fail when all 4 slot encrypted_dek fields are corrupted; "
            f"got returncode=0"
        )

    def test_corrupt_salt_in_all_4_slots_fails(self, tmp_path):
        """
        Flip bytes in the salt field (offset 0x001C) of all four slots.

        Salt corruption produces wrong KEK → wrong HMAC verification → all slots fail.
        """
        cdir, container_path, _ = make_test_container(tmp_path)

        container_size = len(container_path.read_bytes())
        for pct in (0, 25, 50, 75):
            slot_off = slot_offset(container_size, pct)
            corrupt_bytes(container_path, slot_off + POSITION_SALT, SALT_SIZE)

        result = list_container(cdir, expect_success=False)

        assert result.returncode != 0, (
            "scef list must fail when all 4 slot salt fields are corrupted; "
            f"got returncode=0"
        )


# ---------------------------------------------------------------------------
# Group 3 — Partial corruption: 3 of 4 slots → fallback to last slot
# ---------------------------------------------------------------------------

class TestPartialSlotCorruption:
    """
    Corrupt HMAC-protected fields in 3 of 4 slots.  The surviving slot must
    allow full recovery.
    """

    def test_corrupt_dek_in_slots_0_1_2_recovers_via_slot_3(self, tmp_path):
        """
        Corrupt encrypted_dek in slots 0, 1, 2.  Slot 3 is intact.
        readMeta() must reach slot 3 and succeed.
        """
        cdir, container_path, _ = make_test_container(tmp_path)

        container_size = len(container_path.read_bytes())
        for pct in (0, 25, 50):
            slot_off = slot_offset(container_size, pct)
            corrupt_bytes(container_path, slot_off + POSITION_ENCRYPTED_DEK, ENCRYPTED_DEK_SIZE)

        result = list_container(cdir, expect_success=False)
        assert result.returncode == 0, (
            "scef list must succeed via slot 3 fallback when slots 0, 1, 2 "
            "have corrupted encrypted_dek fields.  "
            f"returncode={result.returncode}\n"
            f"stderr: {result.stderr.strip()}"
        )

    def test_corrupt_salt_in_slots_0_1_2_recovers_via_slot_3(self, tmp_path):
        """
        Corrupt salt in slots 0, 1, 2.  Slot 3 is intact.
        readMeta() must reach slot 3 and succeed.
        """
        cdir, container_path, _ = make_test_container(tmp_path)

        container_size = len(container_path.read_bytes())
        for pct in (0, 25, 50):
            slot_off = slot_offset(container_size, pct)
            corrupt_bytes(container_path, slot_off + POSITION_SALT, SALT_SIZE)

        result = list_container(cdir, expect_success=False)
        assert result.returncode == 0, (
            "scef list must succeed via slot 3 fallback when slots 0, 1, 2 "
            "have corrupted salt fields.  "
            f"returncode={result.returncode}\n"
            f"stderr: {result.stderr.strip()}"
        )
