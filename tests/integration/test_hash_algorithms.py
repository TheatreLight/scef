"""
test_hash_algorithms.py - Integration tests for SCEF v1.1 hash selection.

These tests verify the public CLI contract:
- --hash maps to the exact on-disk hash_algo_id values from Header.h.
- The default hash depends on the selected cipher.
- Invalid hash names fail with the documented diagnostic.
"""

import pathlib

import pytest

from conftest import (
    DEFAULT_CONTAINER_SIZE,
    FAST_KDF_ARGS,
    make_text_file,
    run_scef,
)


POSITION_HASH_ALGO_ID = 0x0098
HASH_SHA256 = 0x01
HASH_STREEBOG256 = 0x02
HASH_STREEBOG512 = 0x03


def container_file(container_dir: pathlib.Path) -> pathlib.Path:
    return container_dir / "container.scef"


def header_hash_algo_id(container_dir: pathlib.Path) -> int:
    data = container_file(container_dir).read_bytes()
    return data[POSITION_HASH_ALGO_ID]


def create_with_cipher_hash(
    container_dir: pathlib.Path,
    source: pathlib.Path,
    *,
    cipher: str,
    hash_name: str | None,
):
    args = [
        "create",
        "-c", str(container_dir),
        "-f", str(source),
        "-s", str(DEFAULT_CONTAINER_SIZE),
        "--cipher", cipher,
    ]
    if hash_name is not None:
        args += ["--hash", hash_name]
    args += FAST_KDF_ARGS
    return run_scef(args)


@pytest.mark.parametrize(
    ("cipher", "hash_name", "expected_hash_id"),
    [
        ("aes", None, HASH_SHA256),
        ("kuznechik", None, HASH_STREEBOG512),
        ("aes", "sha256", HASH_SHA256),
        ("aes", "streebog256", HASH_STREEBOG256),
        ("aes", "streebog512", HASH_STREEBOG512),
        ("kuznechik", "sha256", HASH_SHA256),
        ("kuznechik", "streebog256", HASH_STREEBOG256),
        ("kuznechik", "streebog512", HASH_STREEBOG512),
    ],
)
def test_cipher_hash_matrix_sets_expected_hash_algo_id(
    tmp_path, cipher, hash_name, expected_hash_id
):
    cdir = tmp_path / f"c_{cipher}_{hash_name or 'default'}"
    cdir.mkdir()
    src = make_text_file(
        tmp_path / f"{cipher}_{hash_name or 'default'}.txt",
        f"{cipher}/{hash_name or 'default'}\n",
    )

    create_with_cipher_hash(cdir, src, cipher=cipher, hash_name=hash_name)

    assert header_hash_algo_id(cdir) == expected_hash_id


def test_unknown_hash_name_is_rejected_with_expected_message(tmp_path):
    cdir = tmp_path / "c"
    cdir.mkdir()
    src = make_text_file(tmp_path / "data.txt", "invalid hash\n")

    result = run_scef(
        [
            "create",
            "-c", str(cdir),
            "-f", str(src),
            "-s", str(DEFAULT_CONTAINER_SIZE),
            "--hash", "sha1",
        ],
        expect_success=False,
    )

    assert result.returncode != 0
    assert (
        "Unknown hash 'sha1'. Valid values: sha256, sha-256, "
        "streebog256, streebog-256, streebog512, streebog-512"
    ) in (result.stdout + result.stderr)
