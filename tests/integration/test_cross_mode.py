"""
test_cross_mode.py - Chapter 7 audit T6.

Functional test T6: containers written by the native CLI must be readable by
the browser/Node.js implementation.
"""

import pathlib
import shutil
import subprocess

from conftest import DEFAULT_PASSWORD, make_file_with_bytes, run_scef


SCEF_ROOT = pathlib.Path(__file__).resolve().parents[2]
BROWSER_TEST_DIR = SCEF_ROOT / "browser" / "test"
ARGON2_VENDOR = SCEF_ROOT / "browser" / "vendor" / "argon2.umd.min.js"
PASSWORD = DEFAULT_PASSWORD


def _require_node_browser_deps(pytestconfig):
    import pytest

    node = shutil.which("node")
    if node is None:
        pytest.skip("node not found on PATH; browser Node.js tests cannot run")
    if not ARGON2_VENDOR.exists():
        pytest.skip(f"browser Argon2 vendor bundle missing: {ARGON2_VENDOR}")
    return node


def _run_node_script(node: str, script_name: str, container: pathlib.Path, password: str):
    return subprocess.run(
        [node, str(BROWSER_TEST_DIR / script_name), str(container), password],
        cwd=str(SCEF_ROOT / "browser"),
        capture_output=True,
        text=True,
        timeout=300,
    )


def test_cli_container_is_readable_by_browser_node(tmp_path, pytestconfig):
    node = _require_node_browser_deps(pytestconfig)

    input_dir = tmp_path / "inputs"
    container_dir = tmp_path / "container"
    input_dir.mkdir()
    container_dir.mkdir()

    payloads = {
        "hello.txt": "Hello from CLI to browser mode.\n".encode("utf-8"),
        "small.bin": bytes(range(256)),
        "medium.bin": bytes((i * 17 + 3) & 0xFF for i in range(100 * 1024)),
    }
    files = [
        make_file_with_bytes(input_dir / name, data)
        for name, data in payloads.items()
    ]

    args = ["create", "-c", str(container_dir)]
    for file_path in files:
        args += ["-f", str(file_path)]
    args += ["-s", str(2 * 1024 * 1024), "--kdf-profile", "fast"]
    run_scef(args, password=PASSWORD, timeout=300)

    container = container_dir / "container.scef"
    download = _run_node_script(node, "test_download_node.js", container, PASSWORD)
    assert download.returncode == 0, (
        "Browser downloader failed for CLI-created container.\n"
        f"stdout:\n{download.stdout}\n"
        f"stderr:\n{download.stderr}"
    )
    assert download.stdout.count("PASS: checksum matches") == 3, (
        "Expected one checksum match line for each of the 3 files.\n"
        f"stdout:\n{download.stdout}"
    )
    assert "All files PASSED" in download.stdout, download.stdout
    for name in payloads:
        assert f"--- Downloading: {name} ---" in download.stdout, (
            f"Downloader stdout does not mention {name}.\n"
            f"stdout:\n{download.stdout}"
        )

    filetable = _run_node_script(node, "test_filetable_node.js", container, PASSWORD)
    assert filetable.returncode == 0, (
        "Browser file table parser failed for CLI-created container.\n"
        f"stdout:\n{filetable.stdout}\n"
        f"stderr:\n{filetable.stderr}"
    )

    unlock = _run_node_script(node, "test_e2e_unlock_node.js", container, PASSWORD)
    assert unlock.returncode == 0, (
        "Browser unlock flow failed for CLI-created container.\n"
        f"stdout:\n{unlock.stdout}\n"
        f"stderr:\n{unlock.stderr}"
    )
