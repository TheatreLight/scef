"""
conftest.py — shared fixtures and helpers for SCEF CLI integration tests.
"""

import os
import subprocess
import pathlib
import sys
import pytest

# Suppress Windows Error Reporting crash dialogs so that a crashing scef
# binary does not block the test run with an interactive popup.
# SEM_FAILCRITICALERRORS (0x0001) | SEM_NOGPFAULTERRORBOX (0x0002) | SEM_NOOPENFILEERRORBOX (0x8000)
if sys.platform == "win32":
    import ctypes
    ctypes.windll.kernel32.SetErrorMode(0x8003)

# ---------------------------------------------------------------------------
# Resolve project root and binary
# ---------------------------------------------------------------------------

# This file lives at scef/tests/integration/conftest.py.
# Project root is three levels up.
_THIS_DIR = pathlib.Path(__file__).resolve().parent
_SCEF_ROOT = _THIS_DIR.parent.parent          # .../scef/
_PROJECT_ROOT = _SCEF_ROOT.parent             # .../MEPHI_DIPLOMA/

_SCEF_BIN_PATH = _SCEF_ROOT / "build" / "debug" / "scef.exe"

# Resolved once per session; tests skip if binary is absent.
SCEF_BIN = _SCEF_BIN_PATH
_BINARY_AVAILABLE = _SCEF_BIN_PATH.exists()
if not _BINARY_AVAILABLE:
    _BINARY_MISSING_REASON = (
        f"scef binary not found at {_SCEF_BIN_PATH}. "
        "Build the project first (cmake --build)."
    )


# ---------------------------------------------------------------------------
# Pytest session-level fixture: skip all tests if binary is missing
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True, scope="session")
def require_binary():
    """Skip the entire test session if the scef binary cannot be found."""
    if not _BINARY_AVAILABLE:
        pytest.skip(_BINARY_MISSING_REASON)


# ---------------------------------------------------------------------------
# Core helper: run scef with a password
# ---------------------------------------------------------------------------

DEFAULT_PASSWORD = "integration_test_password_123"
# 4 MiB working size for integration tests.
# The structural minimum is 4 * (HEADER_SIZE + DEFAULT_MAX_TABLE_SIZE) = 278528 bytes (~272 KiB).
# 4 MiB is used here to leave comfortable room for multiple data blocks.
DEFAULT_CONTAINER_SIZE = 4 * 1024 * 1024


def run_scef(
    args: list,
    password: str = DEFAULT_PASSWORD,
    timeout: int = 60,
    expect_success: bool = True,
) -> subprocess.CompletedProcess:
    """
    Run the scef binary with the given argument list.

    The password is supplied on stdin followed by a newline. Most commands
    prompt for a password; --help and --version do not, but supplying extra
    stdin is harmless.

    Parameters
    ----------
    args:
        Argument list, e.g. ["create", "-c", str(cdir), "-f", str(f), "-s", "4194304"].
    password:
        Password string to send on stdin.
    timeout:
        Maximum seconds to wait for the subprocess.
    expect_success:
        If True (default), assert returncode == 0 and include stderr in the
        assertion message. Set to False when testing error paths.

    Returns
    -------
    subprocess.CompletedProcess with stdout and stderr as strings.
    """
    cmd = [str(SCEF_BIN)] + [str(a) for a in args]
    result = subprocess.run(
        cmd,
        input=f"{password}\n",
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    if expect_success:
        assert result.returncode == 0, (
            f"scef {' '.join(args[0:1])} failed (rc={result.returncode}).\n"
            f"stderr: {result.stderr.strip()}\n"
            f"stdout: {result.stdout.strip()}"
        )
    return result


# ---------------------------------------------------------------------------
# File creation helpers
# ---------------------------------------------------------------------------

def make_text_file(path: pathlib.Path, content: str = "hello, SCEF\n") -> pathlib.Path:
    """Write a UTF-8 text file and return its path."""
    path.write_text(content, encoding="utf-8")
    return path


def make_binary_file(path: pathlib.Path, size: int, pattern: bytes = b"\xDE\xAD\xBE\xEF") -> pathlib.Path:
    """
    Write a binary file of *size* bytes filled with a repeating pattern.
    Returns the path.
    """
    data = (pattern * ((size // len(pattern)) + 1))[:size]
    path.write_bytes(data)
    return path


def make_file_with_bytes(path: pathlib.Path, data: bytes) -> pathlib.Path:
    """Write exact bytes to a file and return its path."""
    path.write_bytes(data)
    return path


# ---------------------------------------------------------------------------
# High-level workflow helpers used across multiple test modules
# ---------------------------------------------------------------------------

def create_container(
    container_dir: pathlib.Path,
    files: list,
    size: int = DEFAULT_CONTAINER_SIZE,
    password: str = DEFAULT_PASSWORD,
    max_table_size: int = None,
) -> subprocess.CompletedProcess:
    """
    Run 'scef create -c <dir> -f <file1> [-f <file2> ...] -s <size>'.

    Parameters
    ----------
    container_dir:
        Directory where container.scef will be created.
    files:
        List of pathlib.Path objects to include.
    size:
        Container size in bytes.
    password:
        Password for encryption.
    max_table_size:
        Optional --max_table_size value.
    """
    args = ["create", "-c", str(container_dir)]
    for f in files:
        args += ["-f", str(f)]
    args += ["-s", str(size)]
    if max_table_size is not None:
        args += ["--max_table_size", str(max_table_size)]
    return run_scef(args, password=password)


def add_file(
    container_dir: pathlib.Path,
    file: pathlib.Path,
    password: str = DEFAULT_PASSWORD,
) -> subprocess.CompletedProcess:
    """Run 'scef add -c <dir> -f <file>'."""
    return run_scef(["add", "-c", str(container_dir), "-f", str(file)], password=password)


def list_container(
    container_dir: pathlib.Path,
    password: str = DEFAULT_PASSWORD,
    expect_success: bool = True,
) -> subprocess.CompletedProcess:
    """Run 'scef list -c <dir>'."""
    return run_scef(
        ["list", "-c", str(container_dir)],
        password=password,
        expect_success=expect_success,
    )


def extract_files(
    container_dir: pathlib.Path,
    output_dir: pathlib.Path,
    files: list = None,
    password: str = DEFAULT_PASSWORD,
    expect_success: bool = True,
) -> subprocess.CompletedProcess:
    """
    Run 'scef extract -c <dir> -o <output_dir> [-f <file> ...]'.

    If *files* is None, no -f arguments are passed (extract all).
    """
    args = ["extract", "-c", str(container_dir), "-o", str(output_dir)]
    if files:
        for f in files:
            args += ["-f", str(f)]
    return run_scef(args, password=password, expect_success=expect_success)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def scef_bin() -> pathlib.Path:
    """Expose the resolved scef binary path to tests that need it directly."""
    return SCEF_BIN


@pytest.fixture
def container_dir(tmp_path: pathlib.Path) -> pathlib.Path:
    """A fresh temporary directory to hold container.scef."""
    d = tmp_path / "container"
    d.mkdir()
    return d


@pytest.fixture
def input_dir(tmp_path: pathlib.Path) -> pathlib.Path:
    """A fresh temporary directory for source files."""
    d = tmp_path / "inputs"
    d.mkdir()
    return d


@pytest.fixture
def output_dir(tmp_path: pathlib.Path) -> pathlib.Path:
    """A fresh temporary directory for extracted files."""
    d = tmp_path / "outputs"
    d.mkdir()
    return d
