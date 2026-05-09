"""
test_slot_byte_identity.py — Verify that all 4 slot headers are byte-identical
after write.

Spec invariant (FileManager::writeAllSlots / writeFileTableToAllSlots):
  After any successful write operation, all four (Header + FileTable) slots
  must contain byte-for-byte identical content.  A bug where one slot
  receives a different header_version, or where one slot is silently not
  written, would be invisible to functional round-trip tests as long as
  readMeta() successfully reads slot 0.

Slot offset formula (spec, container-format.md:25, FileManager.h:31-34):
  slot_offset(size, N%) = floor(size * N / 100 / HEADER_SIZE) * HEADER_SIZE
  For N=0 always returns 0.

This is NOT the naive formula (size // 4, size // 2, ...) which only
coincidentally agrees for power-of-2 container sizes.
"""

import struct
import pathlib
import pytest

from conftest import (
    DEFAULT_PASSWORD,
    DEFAULT_CONTAINER_SIZE,
    FAST_KDF_ARGS,
    create_container,
    add_file,
    make_text_file,
    make_file_with_bytes,
    run_scef,
)

# ---------------------------------------------------------------------------
# Layout constants (must match Header.h)
# ---------------------------------------------------------------------------

HEADER_SIZE = 4096


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def slot_offset(container_size: int, percent: int) -> int:
    """
    Compute the byte offset of a slot using the spec formula.

    Matches FileManager::computeSlotOffset():
        floor(container_size * percent / 100 / HEADER_SIZE) * HEADER_SIZE
    For percent == 0 always returns 0.
    """
    if percent == 0:
        return 0
    return (container_size * percent // 100 // HEADER_SIZE) * HEADER_SIZE


def read_slot_header(data: bytes, container_size: int, percent: int) -> bytes:
    """Return the HEADER_SIZE bytes at the slot position for the given percent."""
    off = slot_offset(container_size, percent)
    return data[off : off + HEADER_SIZE]


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestAllSlotsByteIdenticalAfterCreate:
    """
    After 'scef create', all four slot headers must be byte-for-byte identical.
    Covers the basic create path.
    """

    def test_all_four_slot_headers_byte_identical_4mib(self, tmp_path):
        """
        Create a container at the default 4 MiB size.  Read the 4096-byte header
        block at each of the four spec-formula slot offsets and assert all four
        are byte-for-byte identical.

        This verifies writeAllSlots() wrote the same content to every slot.
        A bug where slot 0 has a different header_version than slots 1-3 would
        be caught here.
        """
        cdir = tmp_path / "c"
        cdir.mkdir()
        src = make_text_file(tmp_path / "data.txt", "slot identity test\n")

        create_container(cdir, [src], size=DEFAULT_CONTAINER_SIZE)

        container_path = cdir / "container.scef"
        data = container_path.read_bytes()
        container_size = len(data)

        headers = [
            read_slot_header(data, container_size, pct)
            for pct in (0, 25, 50, 75)
        ]

        assert headers[0] == headers[1], (
            f"Slot 0 header (offset {slot_offset(container_size, 0)}) != "
            f"Slot 1 header (offset {slot_offset(container_size, 25)})"
        )
        assert headers[0] == headers[2], (
            f"Slot 0 header (offset {slot_offset(container_size, 0)}) != "
            f"Slot 2 header (offset {slot_offset(container_size, 50)})"
        )
        assert headers[0] == headers[3], (
            f"Slot 0 header (offset {slot_offset(container_size, 0)}) != "
            f"Slot 3 header (offset {slot_offset(container_size, 75)})"
        )

    @pytest.mark.parametrize("container_size", [
        1_000_000,    # non-power-of-2: spec formula diverges from naive size//4
        794624,       # capacity-overflow boundary from test_capacity_overflow
    ])
    def test_all_four_slot_headers_byte_identical_non_power_of_two(
            self, tmp_path, container_size):
        """
        Non-power-of-2 container sizes exercise the slot formula more thoroughly.
        The spec formula must place slots at 4096-aligned offsets; the naive
        formula (size // 4) fails this alignment for non-power-of-2 sizes.

        For container_size=1_000_000:
          spec slot 1 offset: (1_000_000 * 25 // 100 // 4096) * 4096 = 245760
          naive offset: 1_000_000 // 4 = 250000 (not 4096-aligned)
        """
        cdir = tmp_path / "c"
        cdir.mkdir()
        src = make_text_file(tmp_path / "data.txt", "x" * 16)

        create_container(cdir, [src], size=container_size)

        container_path = cdir / "container.scef"
        data = container_path.read_bytes()
        actual_size = len(data)
        assert actual_size == container_size

        headers = [
            read_slot_header(data, actual_size, pct)
            for pct in (0, 25, 50, 75)
        ]

        for i, pct_i in enumerate((0, 25, 50, 75)):
            for j, pct_j in enumerate((0, 25, 50, 75)):
                if i >= j:
                    continue
                assert headers[i] == headers[j], (
                    f"container_size={container_size}: "
                    f"Slot {i} header (offset {slot_offset(actual_size, pct_i)}) != "
                    f"Slot {j} header (offset {slot_offset(actual_size, pct_j)})"
                )


class TestAllSlotsByteIdenticalAfterAdd:
    """
    After 'scef add', all four slot headers must still be byte-identical.
    Covers the add path, which updates header_version and file_count.
    """

    def test_all_four_slot_headers_byte_identical_after_add(self, tmp_path):
        """
        Create a container, then add a second file.  After the add, read all four
        slot headers and assert they are byte-identical.

        The add path must write the updated header (with new file_count and
        incremented header_version) to all four slots, not just slot 0.
        """
        cdir = tmp_path / "c"
        cdir.mkdir()
        src_a = make_text_file(tmp_path / "a.txt", "file A content\n")
        src_b = make_text_file(tmp_path / "b.txt", "file B content\n")

        create_container(cdir, [src_a], size=DEFAULT_CONTAINER_SIZE)
        add_file(cdir, src_b)

        container_path = cdir / "container.scef"
        data = container_path.read_bytes()
        container_size = len(data)

        headers = [
            read_slot_header(data, container_size, pct)
            for pct in (0, 25, 50, 75)
        ]

        assert headers[0] == headers[1] == headers[2] == headers[3], (
            "After 'scef add', all four slot headers must be byte-identical.  "
            "Slot headers differ — the add operation may have updated only some slots."
        )

    def test_header_version_incremented_identically_in_all_slots(self, tmp_path):
        """
        After 'scef add', the header_version field (uint32_le at slot+0x0090)
        must be identical across all four slots, and greater than after create.

        This is a targeted check complementing the full byte-identity test above:
        it verifies that the write-ordering invariant holds even if other header
        fields happen to agree by coincidence.
        """
        cdir = tmp_path / "c"
        cdir.mkdir()
        src_a = make_text_file(tmp_path / "a.txt", "initial\n")
        src_b = make_text_file(tmp_path / "b.txt", "added\n")

        # After create: read header_version from slot 0.
        create_container(cdir, [src_a], size=DEFAULT_CONTAINER_SIZE)
        data_after_create = (cdir / "container.scef").read_bytes()
        size = len(data_after_create)

        version_after_create = struct.unpack_from(
            "<I", data_after_create, slot_offset(size, 0) + 0x0090
        )[0]

        # After add: all four slots must have the same (incremented) version.
        add_file(cdir, src_b)
        data_after_add = (cdir / "container.scef").read_bytes()

        versions = [
            struct.unpack_from("<I", data_after_add, slot_offset(size, pct) + 0x0090)[0]
            for pct in (0, 25, 50, 75)
        ]

        assert versions[0] == versions[1] == versions[2] == versions[3], (
            f"header_version differs across slots after 'scef add': {versions}. "
            f"All four slots must carry the same header_version."
        )
        assert versions[0] > version_after_create, (
            f"header_version was not incremented after 'scef add': "
            f"after_create={version_after_create}, after_add={versions[0]}"
        )
