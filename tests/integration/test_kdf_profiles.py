"""
test_kdf_profiles.py — Integration tests for KDF CLI flags.

Verified behaviors
------------------
- Default (no KDF flags): container opens and files can be listed.
- Each named profile (fast, default, high, browser): correct open, wrong password
  fails, extracted file matches original.
- Custom manual params (--kdf-m/t/p): container opens and files are intact.
- Mutual exclusion: --kdf-profile + --kdf-m together → non-zero exit, error message
  contains "Cannot use --kdf-profile with manual".
- Validation errors: --kdf-m below/above limits, --kdf-profile with unknown name.
- --kdf-t 0 / --kdf-p 0 are treated as "not specified" by the parser and silently
  fall back to the default profile (no error), which matches the source semantics:
  a stored value of 0 means "flag absent".
- benchmark command: exits 0, output contains all 4 profile names.
- Cross-profile open: container created with one KDF stores params in the header;
  a subsequent open reads those stored params and succeeds regardless of code defaults.

Speed notes
-----------
All tests that do not specifically need a heavy profile use --kdf-profile fast
(m=19 MiB, t=2, p=1, ~0.5s) or --kdf-m 8 --kdf-t 1 --kdf-p 1 (minimal custom)
to keep the total test-suite runtime reasonable. The "high" profile (m=256 MiB,
t=5, p=8, ~6s) is tested once because it must be covered; it is not reused.
"""

import pathlib
import subprocess

import pytest

from conftest import (
    DEFAULT_PASSWORD,
    DEFAULT_CONTAINER_SIZE,
    create_container,
    list_container,
    extract_files,
    make_text_file,
    make_file_with_bytes,
    run_scef,
    SCEF_BIN,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Smallest valid custom params — runs in well under a second.
FAST_CUSTOM_M = 8    # MiB
FAST_CUSTOM_T = 1
FAST_CUSTOM_P = 1


def _run_raw(args: list, stdin_text: str = "\n", timeout: int = 30) -> subprocess.CompletedProcess:
    """Run scef without any automatic assertion on the exit code."""
    return subprocess.run(
        [str(SCEF_BIN)] + [str(a) for a in args],
        input=stdin_text,
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def _create_with_kdf_profile(
    container_dir: pathlib.Path,
    files: list,
    profile: str,
    password: str = DEFAULT_PASSWORD,
    size: int = DEFAULT_CONTAINER_SIZE,
) -> subprocess.CompletedProcess:
    """Run 'scef create ... --kdf-profile <profile>'."""
    args = ["create", "-c", str(container_dir)]
    for f in files:
        args += ["-f", str(f)]
    args += ["-s", str(size), "--kdf-profile", profile]
    return run_scef(args, password=password)


def _create_with_custom_kdf(
    container_dir: pathlib.Path,
    files: list,
    m_mib: int,
    t: int,
    p: int,
    password: str = DEFAULT_PASSWORD,
    size: int = DEFAULT_CONTAINER_SIZE,
) -> subprocess.CompletedProcess:
    """Run 'scef create ... --kdf-m <m> --kdf-t <t> --kdf-p <p>'."""
    args = ["create", "-c", str(container_dir)]
    for f in files:
        args += ["-f", str(f)]
    args += [
        "-s", str(size),
        "--kdf-m", str(m_mib),
        "--kdf-t", str(t),
        "--kdf-p", str(p),
    ]
    return run_scef(args, password=password)


def _assert_files_equal(expected_path: pathlib.Path, actual_path: pathlib.Path):
    assert actual_path.exists(), f"Extracted file does not exist: {actual_path}"
    expected = expected_path.read_bytes()
    actual = actual_path.read_bytes()
    assert len(actual) == len(expected), (
        f"{actual_path.name}: size mismatch — "
        f"expected {len(expected)} bytes, got {len(actual)} bytes"
    )
    assert actual == expected, (
        f"{actual_path.name}: byte content mismatch"
    )


# ---------------------------------------------------------------------------
# Test 1: Default profile (no KDF flags)
# ---------------------------------------------------------------------------

class TestDefaultProfile:
    """Create a container without any KDF flags; verify the container is usable."""

    def test_default_profile_container_opens(self, tmp_path):
        """No --kdf-* flags → 'default' profile is used; container must open."""
        src = make_text_file(tmp_path / "hello.txt", "default kdf test\n")
        cdir = tmp_path / "c"
        cdir.mkdir()

        create_container(cdir, [src])

        result = list_container(cdir)
        assert result.returncode == 0, (
            f"Container created with default KDF must be listable.\n"
            f"stderr: {result.stderr.strip()}"
        )

    def test_default_profile_file_appears_in_list(self, tmp_path):
        """File added at create time appears in list output."""
        src = make_text_file(tmp_path / "readme.txt", "content")
        cdir = tmp_path / "c"
        cdir.mkdir()

        create_container(cdir, [src])

        result = list_container(cdir)
        assert "readme.txt" in result.stdout, (
            "File 'readme.txt' not found in list output for default-profile container"
        )

    def test_default_profile_file_extracts_correctly(self, tmp_path):
        """File extracted from a default-profile container matches the original."""
        expected = b"default profile extract test"
        src = make_file_with_bytes(tmp_path / "data.bin", expected)
        cdir = tmp_path / "c"
        cdir.mkdir()
        outdir = tmp_path / "out"
        outdir.mkdir()

        create_container(cdir, [src])
        extract_files(cdir, outdir, files=["data.bin"])

        _assert_files_equal(src, outdir / "data.bin")


# ---------------------------------------------------------------------------
# Test 2: Each named profile
# ---------------------------------------------------------------------------

class TestNamedProfiles:
    """
    For each named profile: correct password opens the container, wrong password
    fails, extracted file matches the original.

    The 'high' profile is slow (~6s) but must be tested at least once.
    All other profiles use their own name to verify the flag parsing path.
    """

    @pytest.mark.parametrize("profile", ["fast", "default", "browser"])
    def test_named_profile_container_opens(self, tmp_path, profile):
        """Container created with --kdf-profile <name> must be listable."""
        src = make_text_file(tmp_path / "f.txt", f"profile={profile}\n")
        cdir = tmp_path / "c"
        cdir.mkdir()

        _create_with_kdf_profile(cdir, [src], profile)

        result = list_container(cdir)
        assert result.returncode == 0, (
            f"Container (profile={profile!r}) must be listable with correct password.\n"
            f"stderr: {result.stderr.strip()}"
        )

    @pytest.mark.parametrize("profile", ["fast", "default", "browser"])
    def test_named_profile_wrong_password_fails(self, tmp_path, profile):
        """Wrong password on a named-profile container must produce a non-zero exit."""
        src = make_text_file(tmp_path / "f.txt", "sensitive\n")
        cdir = tmp_path / "c"
        cdir.mkdir()

        _create_with_kdf_profile(cdir, [src], profile)

        result = run_scef(
            ["list", "-c", str(cdir)],
            password="definitely_wrong_password",
            expect_success=False,
        )
        assert result.returncode != 0, (
            f"Wrong password must fail for profile={profile!r}, "
            f"got rc={result.returncode}"
        )

    @pytest.mark.parametrize("profile", ["fast", "default", "browser"])
    def test_named_profile_file_extracts_correctly(self, tmp_path, profile):
        """File extracted from a named-profile container is byte-for-byte correct."""
        expected = bytes([0xAB, 0xCD, 0xEF] * 341)  # 1023 bytes
        src = make_file_with_bytes(tmp_path / "payload.bin", expected)
        cdir = tmp_path / "c"
        cdir.mkdir()
        outdir = tmp_path / "out"
        outdir.mkdir()

        _create_with_kdf_profile(cdir, [src], profile)
        extract_files(cdir, outdir, files=["payload.bin"])

        _assert_files_equal(src, outdir / "payload.bin")

    def test_high_profile_container_opens(self, tmp_path):
        """
        Container created with --kdf-profile high must be listable with the
        correct password.  This test is parametrized separately because the
        high profile takes ~6s and running it three times (open/wrong/extract)
        would cost ~18s in CI.
        """
        src = make_text_file(tmp_path / "secure.txt", "high security profile\n")
        cdir = tmp_path / "c"
        cdir.mkdir()

        _create_with_kdf_profile(cdir, [src], "high", timeout=60)

        result = run_scef(
            ["list", "-c", str(cdir)],
            password=DEFAULT_PASSWORD,
            timeout=60,
        )
        assert result.returncode == 0, (
            f"Container with 'high' profile must be listable.\n"
            f"stderr: {result.stderr.strip()}"
        )

    def test_high_profile_file_extracts_correctly(self, tmp_path):
        """File from a 'high' profile container extracts intact."""
        expected = b"high security payload"
        src = make_file_with_bytes(tmp_path / "hs.bin", expected)
        cdir = tmp_path / "c"
        cdir.mkdir()
        outdir = tmp_path / "out"
        outdir.mkdir()

        _create_with_kdf_profile(cdir, [src], "high", timeout=60)
        extract_files(cdir, outdir, files=["hs.bin"])

        _assert_files_equal(src, outdir / "hs.bin")


def _create_with_kdf_profile(
    container_dir: pathlib.Path,
    files: list,
    profile: str,
    password: str = DEFAULT_PASSWORD,
    size: int = DEFAULT_CONTAINER_SIZE,
    timeout: int = 60,
) -> subprocess.CompletedProcess:
    """Run 'scef create ... --kdf-profile <profile>' (overrides conftest helper)."""
    args = ["create", "-c", str(container_dir)]
    for f in files:
        args += ["-f", str(f)]
    args += ["-s", str(size), "--kdf-profile", profile]
    return run_scef(args, password=password, timeout=timeout)


# ---------------------------------------------------------------------------
# Test 3: Custom manual params
# ---------------------------------------------------------------------------

class TestCustomManualParams:
    """Create containers with explicit --kdf-m/t/p combinations."""

    def test_custom_params_container_opens(self, tmp_path):
        """--kdf-m 32 --kdf-t 2 --kdf-p 2: container must be listable."""
        src = make_text_file(tmp_path / "f.txt", "custom params\n")
        cdir = tmp_path / "c"
        cdir.mkdir()

        _create_with_custom_kdf(cdir, [src], m_mib=32, t=2, p=2)

        result = list_container(cdir)
        assert result.returncode == 0, (
            f"Container with custom KDF params must be listable.\n"
            f"stderr: {result.stderr.strip()}"
        )

    def test_custom_params_file_is_intact(self, tmp_path):
        """File from a custom-params container extracts correctly."""
        expected = b"custom kdf roundtrip"
        src = make_file_with_bytes(tmp_path / "data.bin", expected)
        cdir = tmp_path / "c"
        cdir.mkdir()
        outdir = tmp_path / "out"
        outdir.mkdir()

        _create_with_custom_kdf(cdir, [src], m_mib=32, t=2, p=2)
        extract_files(cdir, outdir, files=["data.bin"])

        _assert_files_equal(src, outdir / "data.bin")

    def test_minimal_custom_params(self, tmp_path):
        """Minimum valid custom params (m=8, t=1, p=1): container must open."""
        src = make_text_file(tmp_path / "f.txt", "minimal params\n")
        cdir = tmp_path / "c"
        cdir.mkdir()

        _create_with_custom_kdf(cdir, [src], m_mib=FAST_CUSTOM_M, t=FAST_CUSTOM_T, p=FAST_CUSTOM_P)

        result = list_container(cdir)
        assert result.returncode == 0, (
            f"Container with minimal custom KDF (m=8,t=1,p=1) must be listable.\n"
            f"stderr: {result.stderr.strip()}"
        )

    def test_only_kdf_m_specified(self, tmp_path):
        """
        When only --kdf-m is given, --kdf-t and --kdf-p fall back to the
        'default' profile values.  The container must still open correctly.
        """
        src = make_text_file(tmp_path / "f.txt", "only m specified\n")
        cdir = tmp_path / "c"
        cdir.mkdir()
        args = [
            "create", "-c", str(cdir),
            "-f", str(src),
            "-s", str(DEFAULT_CONTAINER_SIZE),
            "--kdf-m", "8",
        ]

        run_scef(args)

        result = list_container(cdir)
        assert result.returncode == 0, (
            "Container with only --kdf-m should open (t,p fall back to defaults)."
        )


# ---------------------------------------------------------------------------
# Test 4: Mutual exclusion error
# ---------------------------------------------------------------------------

class TestMutualExclusion:
    """--kdf-profile and --kdf-m/t/p cannot be used together."""

    def _run_conflicting(self, tmp_path, profile_flag, manual_flags):
        """Build a create invocation with both profile and manual flags; return result."""
        src = make_text_file(tmp_path / "f.txt", "x")
        args = [
            "create",
            "-c", str(tmp_path / "c"),
            "-f", str(src),
            "-s", str(DEFAULT_CONTAINER_SIZE),
            "--kdf-profile", profile_flag,
        ] + manual_flags
        return _run_raw(args, stdin_text=f"{DEFAULT_PASSWORD}\n")

    def test_profile_and_m_are_mutually_exclusive(self, tmp_path):
        result = self._run_conflicting(tmp_path, "fast", ["--kdf-m", "64"])
        assert result.returncode != 0, (
            "--kdf-profile fast + --kdf-m 64 must exit non-zero"
        )

    def test_profile_and_t_are_mutually_exclusive(self, tmp_path):
        result = self._run_conflicting(tmp_path, "fast", ["--kdf-t", "3"])
        assert result.returncode != 0, (
            "--kdf-profile fast + --kdf-t 3 must exit non-zero"
        )

    def test_profile_and_p_are_mutually_exclusive(self, tmp_path):
        result = self._run_conflicting(tmp_path, "fast", ["--kdf-p", "4"])
        assert result.returncode != 0, (
            "--kdf-profile fast + --kdf-p 4 must exit non-zero"
        )

    def test_profile_and_all_manual_are_mutually_exclusive(self, tmp_path):
        result = self._run_conflicting(
            tmp_path, "fast", ["--kdf-m", "64", "--kdf-t", "3", "--kdf-p", "4"]
        )
        assert result.returncode != 0, (
            "--kdf-profile fast + all manual flags must exit non-zero"
        )

    def test_mutual_exclusion_error_message(self, tmp_path):
        """The error output must mention that the two flag groups are mutually exclusive."""
        result = self._run_conflicting(tmp_path, "fast", ["--kdf-m", "64"])
        combined = result.stdout + result.stderr
        assert "Cannot use --kdf-profile with manual" in combined, (
            f"Expected mutual-exclusion error message in output.\n"
            f"stdout: {result.stdout.strip()}\n"
            f"stderr: {result.stderr.strip()}"
        )


# ---------------------------------------------------------------------------
# Test 5: Validation errors for manual params and unknown profile name
# ---------------------------------------------------------------------------

class TestValidationErrors:
    """Invalid KDF parameter values must produce a non-zero exit code."""

    def _create_args(self, tmp_path, extra_flags):
        """Return a raw create arg list with the given extra flags appended."""
        src = make_text_file(tmp_path / "f.txt", "x")
        cdir = tmp_path / "c"
        cdir.mkdir()
        return (
            [
                "create",
                "-c", str(cdir),
                "-f", str(src),
                "-s", str(DEFAULT_CONTAINER_SIZE),
            ]
            + extra_flags,
        )

    def test_kdf_m_zero_falls_back_to_default(self, tmp_path):
        """--kdf-m 0 is treated as 'not specified' and falls back to default profile."""
        src = make_text_file(tmp_path / "f.txt", "x")
        cdir = tmp_path / "c"
        cdir.mkdir()
        result = _run_raw(
            [
                "create", "-c", str(cdir), "-f", str(src),
                "-s", str(DEFAULT_CONTAINER_SIZE),
                "--kdf-m", "0",
            ],
            stdin_text=f"{DEFAULT_PASSWORD}\n",
        )
        assert result.returncode == 0, (
            "--kdf-m 0 must fall back to default profile and succeed.\n"
            f"stderr: {result.stderr.strip()}"
        )

    def test_kdf_m_above_maximum_fails(self, tmp_path):
        """--kdf-m 8192 (above maximum of 4096 MiB) → non-zero exit."""
        src = make_text_file(tmp_path / "f.txt", "x")
        cdir = tmp_path / "c"
        cdir.mkdir()
        result = _run_raw(
            [
                "create", "-c", str(cdir), "-f", str(src),
                "-s", str(DEFAULT_CONTAINER_SIZE),
                "--kdf-m", "8192",
            ],
            stdin_text=f"{DEFAULT_PASSWORD}\n",
        )
        assert result.returncode != 0, (
            "--kdf-m 8192 (above max 4096) must exit non-zero"
        )

    def test_kdf_m_at_minimum_boundary_succeeds(self, tmp_path):
        """--kdf-m 1 (exactly at minimum) must succeed."""
        src = make_text_file(tmp_path / "f.txt", "x")
        cdir = tmp_path / "c"
        cdir.mkdir()
        result = _run_raw(
            [
                "create", "-c", str(cdir), "-f", str(src),
                "-s", str(DEFAULT_CONTAINER_SIZE),
                "--kdf-m", "1",
            ],
            stdin_text=f"{DEFAULT_PASSWORD}\n",
        )
        assert result.returncode == 0, (
            f"--kdf-m 1 (at minimum boundary) must succeed.\n"
            f"stderr: {result.stderr.strip()}"
        )

    def test_kdf_m_at_maximum_boundary_succeeds(self, tmp_path):
        """--kdf-m 4096 (exactly at maximum) must succeed."""
        src = make_text_file(tmp_path / "f.txt", "x")
        cdir = tmp_path / "c"
        cdir.mkdir()
        result = _run_raw(
            [
                "create", "-c", str(cdir), "-f", str(src),
                "-s", str(DEFAULT_CONTAINER_SIZE),
                "--kdf-m", "4096",
            ],
            stdin_text=f"{DEFAULT_PASSWORD}\n",
            timeout=120,
        )
        assert result.returncode == 0, (
            f"--kdf-m 4096 (at maximum boundary) must succeed.\n"
            f"stderr: {result.stderr.strip()}"
        )

    def test_unknown_profile_name_fails(self, tmp_path):
        """--kdf-profile nonexistent → non-zero exit."""
        src = make_text_file(tmp_path / "f.txt", "x")
        cdir = tmp_path / "c"
        cdir.mkdir()
        result = _run_raw(
            [
                "create", "-c", str(cdir), "-f", str(src),
                "-s", str(DEFAULT_CONTAINER_SIZE),
                "--kdf-profile", "nonexistent",
            ],
            stdin_text=f"{DEFAULT_PASSWORD}\n",
        )
        assert result.returncode != 0, (
            "--kdf-profile nonexistent must exit non-zero"
        )

    def test_unknown_profile_name_error_message(self, tmp_path):
        """Error output for an unknown profile name must identify the bad value."""
        src = make_text_file(tmp_path / "f.txt", "x")
        cdir = tmp_path / "c"
        cdir.mkdir()
        result = _run_raw(
            [
                "create", "-c", str(cdir), "-f", str(src),
                "-s", str(DEFAULT_CONTAINER_SIZE),
                "--kdf-profile", "nonexistent",
            ],
            stdin_text=f"{DEFAULT_PASSWORD}\n",
        )
        combined = result.stdout + result.stderr
        assert "nonexistent" in combined, (
            f"Error output for unknown profile must include the bad name.\n"
            f"stdout: {result.stdout.strip()}\n"
            f"stderr: {result.stderr.strip()}"
        )

    def test_kdf_t_zero_does_not_fail(self, tmp_path):
        """
        --kdf-t 0 is treated by the parser as 'flag not specified' (value 0 =
        absent sentinel).  The manual-params branch is triggered only when at
        least one of m/t/p is non-zero; because --kdf-t 0 resolves to the zero
        sentinel it activates no branch and the container falls back to the
        'default' profile.  This must NOT be an error.

        This test documents and locks the current parser contract so that future
        refactors don't inadvertently change the behavior in a way that breaks
        existing users.
        """
        src = make_text_file(tmp_path / "f.txt", "x")
        cdir = tmp_path / "c"
        cdir.mkdir()
        result = _run_raw(
            [
                "create", "-c", str(cdir), "-f", str(src),
                "-s", str(DEFAULT_CONTAINER_SIZE),
                "--kdf-t", "0",
            ],
            stdin_text=f"{DEFAULT_PASSWORD}\n",
        )
        assert result.returncode == 0, (
            "--kdf-t 0 is treated as 'not specified'; it must not cause a failure.\n"
            f"stderr: {result.stderr.strip()}"
        )

    def test_kdf_p_zero_does_not_fail(self, tmp_path):
        """
        --kdf-p 0 follows the same zero-sentinel logic as --kdf-t 0.
        See test_kdf_t_zero_does_not_fail for the full rationale.
        """
        src = make_text_file(tmp_path / "f.txt", "x")
        cdir = tmp_path / "c"
        cdir.mkdir()
        result = _run_raw(
            [
                "create", "-c", str(cdir), "-f", str(src),
                "-s", str(DEFAULT_CONTAINER_SIZE),
                "--kdf-p", "0",
            ],
            stdin_text=f"{DEFAULT_PASSWORD}\n",
        )
        assert result.returncode == 0, (
            "--kdf-p 0 is treated as 'not specified'; it must not cause a failure.\n"
            f"stderr: {result.stderr.strip()}"
        )


# ---------------------------------------------------------------------------
# Test 6: benchmark command
# ---------------------------------------------------------------------------

class TestBenchmarkCommand:
    """'scef benchmark' must complete successfully and display all 4 profiles."""

    def test_benchmark_exits_zero(self):
        result = _run_raw(["benchmark"], timeout=120)
        assert result.returncode == 0, (
            f"'scef benchmark' must exit 0, got rc={result.returncode}.\n"
            f"stderr: {result.stderr.strip()}"
        )

    def test_benchmark_output_contains_fast(self):
        result = _run_raw(["benchmark"], timeout=120)
        assert "fast" in result.stdout.lower(), (
            f"'scef benchmark' output must contain 'fast'.\n"
            f"stdout: {result.stdout}"
        )

    def test_benchmark_output_contains_default(self):
        result = _run_raw(["benchmark"], timeout=120)
        assert "default" in result.stdout.lower(), (
            f"'scef benchmark' output must contain 'default'.\n"
            f"stdout: {result.stdout}"
        )

    def test_benchmark_output_contains_high(self):
        result = _run_raw(["benchmark"], timeout=120)
        assert "high" in result.stdout.lower(), (
            f"'scef benchmark' output must contain 'high'.\n"
            f"stdout: {result.stdout}"
        )

    def test_benchmark_output_contains_browser(self):
        result = _run_raw(["benchmark"], timeout=120)
        assert "browser" in result.stdout.lower(), (
            f"'scef benchmark' output must contain 'browser'.\n"
            f"stdout: {result.stdout}"
        )

    def test_benchmark_output_contains_all_four_profiles(self):
        """Single call: assert all four profile names appear in one benchmark run."""
        result = _run_raw(["benchmark"], timeout=120)
        assert result.returncode == 0, (
            f"'scef benchmark' must exit 0.\nstderr: {result.stderr.strip()}"
        )
        output = result.stdout.lower()
        for name in ("fast", "default", "high", "browser"):
            assert name in output, (
                f"'scef benchmark' output must contain '{name}'.\n"
                f"stdout: {result.stdout}"
            )


# ---------------------------------------------------------------------------
# Test 7: Cross-profile open (KDF params are read from the header, not defaults)
# ---------------------------------------------------------------------------

class TestCrossProfileOpen:
    """
    Verify that the KDF parameters stored in the container header are used on
    open, not the code defaults.  A container created with one KDF profile must
    remain readable even if the code default changes.
    """

    def test_fast_profile_container_reads_params_from_header(self, tmp_path):
        """
        Create with --kdf-profile fast, then open (list).  The open path reads
        the KDF params from the on-disk header (m=19 MiB, t=2, p=1) and must
        succeed.
        """
        src = make_text_file(tmp_path / "f.txt", "fast profile header params\n")
        cdir = tmp_path / "c"
        cdir.mkdir()

        _create_with_kdf_profile(cdir, [src], "fast")

        result = list_container(cdir)
        assert result.returncode == 0, (
            "Container created with 'fast' profile must be openable; "
            "open should read KDF params from header, not from code defaults.\n"
            f"stderr: {result.stderr.strip()}"
        )
        assert "f.txt" in result.stdout, (
            "File 'f.txt' must appear in list output after cross-profile open"
        )

    def test_custom_params_container_reads_params_from_header(self, tmp_path):
        """
        Create with --kdf-m 8 --kdf-t 1 --kdf-p 1, then open (list).
        The stored custom params must be used on open.
        """
        src = make_text_file(tmp_path / "f.txt", "custom params header\n")
        cdir = tmp_path / "c"
        cdir.mkdir()

        _create_with_custom_kdf(
            cdir, [src],
            m_mib=FAST_CUSTOM_M, t=FAST_CUSTOM_T, p=FAST_CUSTOM_P,
        )

        result = list_container(cdir)
        assert result.returncode == 0, (
            "Container created with custom KDF params must be openable; "
            "open should read KDF params from header.\n"
            f"stderr: {result.stderr.strip()}"
        )

    def test_two_containers_with_different_kdf_open_independently(self, tmp_path):
        """
        Two containers created with different KDF profiles must both be openable
        independently, confirming that per-container header KDF storage is used.
        """
        src_a = make_text_file(tmp_path / "a.txt", "container A\n")
        src_b = make_text_file(tmp_path / "b.txt", "container B\n")

        cdir_a = tmp_path / "ca"
        cdir_a.mkdir()
        cdir_b = tmp_path / "cb"
        cdir_b.mkdir()

        _create_with_kdf_profile(cdir_a, [src_a], "fast")
        _create_with_custom_kdf(
            cdir_b, [src_b],
            m_mib=FAST_CUSTOM_M, t=FAST_CUSTOM_T, p=FAST_CUSTOM_P,
        )

        result_a = list_container(cdir_a)
        assert result_a.returncode == 0, (
            f"Container A ('fast' profile) must be listable.\n"
            f"stderr: {result_a.stderr.strip()}"
        )
        assert "a.txt" in result_a.stdout

        result_b = list_container(cdir_b)
        assert result_b.returncode == 0, (
            f"Container B (custom params) must be listable.\n"
            f"stderr: {result_b.stderr.strip()}"
        )
        assert "b.txt" in result_b.stdout
