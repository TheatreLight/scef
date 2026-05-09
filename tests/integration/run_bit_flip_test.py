"""
Standalone script to run the single-bit-flip regression test without pytest.
Verifies that scef list recovers from a one-bit corruption in slot 0 header
by falling back to backup slots 1-3.
"""

import subprocess
import pathlib
import sys
import tempfile

# Locate the scef binary in a cross-platform manner.
# On Windows the executable has a .exe suffix; on Linux/macOS it does not.
_BUILD_DIR = pathlib.Path(__file__).resolve().parent.parent.parent / "build" / "debug"
_SCEF_BIN_WIN   = _BUILD_DIR / "scef.exe"
_SCEF_BIN_POSIX = _BUILD_DIR / "scef"

if _SCEF_BIN_WIN.exists():
    SCEF_BIN = _SCEF_BIN_WIN
elif _SCEF_BIN_POSIX.exists():
    SCEF_BIN = _SCEF_BIN_POSIX
else:
    # Fallback: use platform heuristic so the error message is informative.
    SCEF_BIN = _SCEF_BIN_WIN if sys.platform == "win32" else _SCEF_BIN_POSIX
DEFAULT_PASSWORD = "integration_test_password_123"
DEFAULT_CONTAINER_SIZE = 4 * 1024 * 1024


def run_scef(args, password=DEFAULT_PASSWORD, timeout=60):
    cmd = [str(SCEF_BIN)] + [str(a) for a in args]
    return subprocess.run(
        cmd,
        input=f"{password}\n",
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def main():
    if not SCEF_BIN.exists():
        print(f"ERROR: scef binary not found at {SCEF_BIN}", file=sys.stderr)
        sys.exit(1)

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = pathlib.Path(tmpdir)
        cdir = tmp / "c"
        cdir.mkdir()

        # Write a small source file.
        src = tmp / "f.txt"
        src.write_text("content", encoding="utf-8")

        # Create a container with that file.
        # Use minimal KDF params to keep the script fast (same as integration tests).
        r = run_scef(["create", "-c", str(cdir), "-f", str(src),
                      "-s", str(DEFAULT_CONTAINER_SIZE),
                      "--kdf-m", "1", "--kdf-t", "1", "--kdf-p", "1"])
        if r.returncode != 0:
            print(f"FAIL: create failed (rc={r.returncode})\nstderr: {r.stderr}", file=sys.stderr)
            sys.exit(1)

        container_path = cdir / "container.scef"
        data = bytearray(container_path.read_bytes())

        # Flip a bit at offset 0x10 (kdf_m_kib field in slot 0 header).
        data[0x10] ^= 0x01
        container_path.write_bytes(bytes(data))

        # list should succeed by falling back to slot 1.
        r = run_scef(["list", "-c", str(cdir)])
        if r.returncode != 0:
            print(f"FAIL: list returned rc={r.returncode} after single-bit flip in slot 0\n"
                  f"stderr: {r.stderr}\nstdout: {r.stdout}", file=sys.stderr)
            sys.exit(1)

        print(f"PASS: list succeeded after single-bit flip in slot 0 header (rc={r.returncode})")
        print(f"stdout: {r.stdout.strip()}")
        sys.exit(0)


if __name__ == "__main__":
    main()
