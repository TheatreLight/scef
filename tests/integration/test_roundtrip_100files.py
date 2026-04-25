"""
test_roundtrip_100files.py - Chapter 7 audit T1.

Functional test T1: 100-file container round-trip with byte-for-byte
verification after extraction.
"""

import hashlib
import math
import pathlib
import random
import re

import pytest

from conftest import (
    DEFAULT_PASSWORD,
    FAST_KDF_ARGS,
    extract_files,
    list_container,
    make_file_with_bytes,
    run_scef,
)


HEADER_SIZE = 4096
DEFAULT_MAX_TABLE_SIZE = 65536
SLOT_OVERHEAD = 4 * (HEADER_SIZE + DEFAULT_MAX_TABLE_SIZE)
MINIMAL_CONTAINER_SIZE = SLOT_OVERHEAD
MIB = 1024 * 1024
PASSWORD = DEFAULT_PASSWORD


def _round_up_to_mib(size: int) -> int:
    return math.ceil(size / MIB) * MIB


def _deterministic_payload(rng: random.Random, size: int) -> bytes:
    return bytes(rng.getrandbits(8) for _ in range(size))


def _sha256(path: pathlib.Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _listed_names(stdout: str) -> list[str]:
    return re.findall(r"^\s*name:\s*(.+?)\s*$", stdout, flags=re.MULTILINE)


def _create_container_with_initial_file(
    container_dir: pathlib.Path,
    initial_file: pathlib.Path,
    size: int,
) -> None:
    # Current CLI requires at least one -f during create, while the audit flow
    # describes empty create followed by add. Keep this visible and still
    # verify the 100-file round-trip contract.
    run_scef(
        [
            "create",
            "-c",
            str(container_dir),
            "-f",
            str(initial_file),
            "-s",
            str(size),
            *FAST_KDF_ARGS,
        ],
        password=PASSWORD,
        timeout=300,
    )


def _add_files_in_batches(
    container_dir: pathlib.Path,
    files: list[pathlib.Path],
    batch_size: int = 25,
) -> None:
    for start in range(0, len(files), batch_size):
        batch = files[start : start + batch_size]
        args = ["add", "-c", str(container_dir)]
        for path in batch:
            args += ["-f", str(path)]
        run_scef(args, password=PASSWORD, timeout=300)


@pytest.mark.slow
def test_roundtrip_100_files_byte_compare(tmp_path):
    rng = random.Random(0)
    sizes = (
        [10 * 1024] * 10
        + [1 * MIB] * 10
        + [rng.randint(1, 65536) for _ in range(80)]
    )

    input_dir = tmp_path / "inputs"
    container_dir = tmp_path / "container"
    output_dir = tmp_path / "outputs"
    input_dir.mkdir()
    container_dir.mkdir()
    output_dir.mkdir()

    sources = []
    for index, size in enumerate(sizes):
        path = input_dir / f"file_{index:03d}.bin"
        sources.append(make_file_with_bytes(path, _deterministic_payload(rng, size)))

    total_payload = sum(sizes)
    container_size = _round_up_to_mib(
        max(MINIMAL_CONTAINER_SIZE, total_payload + total_payload // 10 + SLOT_OVERHEAD)
    )

    _create_container_with_initial_file(container_dir, sources[0], container_size)
    _add_files_in_batches(container_dir, sources[1:])

    listing = list_container(container_dir, password=PASSWORD)
    names = _listed_names(listing.stdout)
    expected_names = [path.name for path in sources]
    assert len(names) == 100, (
        f"Expected exactly 100 file table entries, got {len(names)}.\n"
        f"stdout:\n{listing.stdout}"
    )
    assert set(names) == set(expected_names), (
        "Listed file names do not match input files.\n"
        f"missing: {sorted(set(expected_names) - set(names))}\n"
        f"extra: {sorted(set(names) - set(expected_names))}"
    )

    extract_files(container_dir, output_dir, files=None, password=PASSWORD, expect_success=True)

    for src in sources:
        extracted = output_dir / src.name
        assert extracted.exists(), f"Extracted file missing: {extracted}"
        assert _sha256(src) == _sha256(extracted), (
            f"SHA-256 mismatch after round-trip for {src.name}"
        )
