"""
Integration tests for the native Kuznechik-GCM cipher path.
"""

import pathlib
import subprocess

from conftest import (
    DEFAULT_PASSWORD,
    SCEF_BIN,
    add_file,
    extract_files,
    list_container,
    make_file_with_bytes,
    make_text_file,
    run_scef,
)


CONTAINER_SIZE = 1024 * 1024
FAST_KDF_ARGS = ["--kdf-m", "64", "--kdf-t", "1", "--kdf-p", "1"]


def _run_raw(args: list, stdin_text: str = "\n", timeout: int = 60) -> subprocess.CompletedProcess:
    return subprocess.run(
        [str(SCEF_BIN)] + [str(a) for a in args],
        input=stdin_text,
        capture_output=True,
        text=True,
        timeout=timeout,
        encoding="utf-8",
    )


def _create_with_cipher(
    container_dir: pathlib.Path,
    files: list[pathlib.Path],
    cipher: str | None = None,
    password: str = DEFAULT_PASSWORD,
) -> subprocess.CompletedProcess:
    args = ["create", "-c", str(container_dir)]
    for file in files:
        args += ["-f", str(file)]
    args += ["-s", str(CONTAINER_SIZE)]
    if cipher is not None:
        args += ["--cipher", cipher]
    args += FAST_KDF_ARGS
    return run_scef(args, password=password)


def _assert_files_equal(expected_path: pathlib.Path, actual_path: pathlib.Path):
    assert actual_path.exists(), f"Extracted file does not exist: {actual_path}"
    assert actual_path.read_bytes() == expected_path.read_bytes()


def _header_cipher_byte(container_dir: pathlib.Path) -> int:
    with (container_dir / "container.scef").open("rb") as f:
        f.seek(0x000C)
        return f.read(1)[0]


def test_kuznechik_round_trip(tmp_path):
    src1 = make_file_with_bytes(tmp_path / "plain.bin", bytes(range(128)))
    src2 = make_text_file(tmp_path / "added.txt", "added through sticky cipher\n")
    cdir = tmp_path / "c"
    outdir = tmp_path / "out"
    cdir.mkdir()
    outdir.mkdir()

    _create_with_cipher(cdir, [src1], "kuznechik")
    add_file(cdir, src2)
    extract_files(cdir, outdir)

    _assert_files_equal(src1, outdir / "plain.bin")
    _assert_files_equal(src2, outdir / "added.txt")


def test_header_cipher_byte_for_kuznechik_and_aes(tmp_path):
    src_k = make_text_file(tmp_path / "k.txt", "kuznechik\n")
    src_a = make_text_file(tmp_path / "a.txt", "aes\n")
    cdir_k = tmp_path / "ck"
    cdir_a = tmp_path / "ca"
    cdir_k.mkdir()
    cdir_a.mkdir()

    _create_with_cipher(cdir_k, [src_k], "kuznechik")
    _create_with_cipher(cdir_a, [src_a], "aes")

    assert _header_cipher_byte(cdir_k) == 0x02
    assert _header_cipher_byte(cdir_a) == 0x01


def test_kuznechik_wrong_password_rejected(tmp_path):
    src = make_text_file(tmp_path / "secret.txt", "secret\n")
    cdir = tmp_path / "c"
    cdir.mkdir()

    _create_with_cipher(cdir, [src], "kuznechik")

    result = list_container(cdir, password="not_the_password", expect_success=False)
    combined = (result.stdout + result.stderr).lower()
    assert result.returncode != 0
    assert "wrong password" in combined or "authentication" in combined


def test_kuznechik_cipher_is_sticky(tmp_path):
    src1 = make_text_file(tmp_path / "one.txt", "one\n")
    src2 = make_text_file(tmp_path / "two.txt", "two\n")
    cdir = tmp_path / "c"
    outdir = tmp_path / "out"
    cdir.mkdir()
    outdir.mkdir()

    _create_with_cipher(cdir, [src1], "kuznechik")
    add_file(cdir, src2)

    listed = list_container(cdir)
    assert listed.returncode == 0
    assert "one.txt" in listed.stdout
    assert "two.txt" in listed.stdout

    extract_files(cdir, outdir, files=["one.txt", "two.txt"])
    _assert_files_equal(src1, outdir / "one.txt")
    _assert_files_equal(src2, outdir / "two.txt")


def test_invalid_cipher_value_rejected(tmp_path):
    src = make_text_file(tmp_path / "f.txt", "x")
    cdir = tmp_path / "c"
    cdir.mkdir()

    result = _run_raw(
        [
            "create", "-c", str(cdir), "-f", str(src),
            "-s", str(CONTAINER_SIZE),
            "--cipher", "blowfish",
        ],
        stdin_text=f"{DEFAULT_PASSWORD}\n",
    )
    combined = result.stdout + result.stderr
    assert result.returncode != 0
    assert "Unknown cipher 'blowfish'" in combined


def test_cipher_header_tamper_makes_container_unreadable(tmp_path):
    src = make_text_file(tmp_path / "payload.txt", "cipher binding\n")
    cdir = tmp_path / "c"
    cdir.mkdir()

    _create_with_cipher(cdir, [src], "kuznechik")

    container = cdir / "container.scef"
    size = container.stat().st_size
    offsets = [(size * pct // 100 // 4096) * 4096 for pct in (0, 25, 50, 75)]
    with container.open("r+b") as f:
        for offset in offsets:
            f.seek(offset + 0x000C)
            f.write(bytes([0x01]))

    result = list_container(cdir, expect_success=False)
    combined = (result.stdout + result.stderr).lower()
    assert result.returncode != 0
    assert "authentication" in combined or "hmac" in combined or "wrong password" in combined
