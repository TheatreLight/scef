"""
test_container_naming.py — Tests for container auto-naming, --name flag, and
single-scef fallback on open.

Spec behavior (Wave 2/3 locked decisions, main.cpp):

CREATE:
  - No --name: use nextAvailableContainerPath(dir).
      * If container.scef does not exist → create container.scef
      * If container.scef exists → create container_1.scef
      * If container_1.scef also exists → create container_2.scef
      * ...never overwrites an existing file.
  - With --name <filename>: create dir/<filename>.
      * <filename> must not contain '/' or '\\' (path separators rejected).

OPEN (list/extract/add):
  - With --name <filename>: open dir/<filename> unconditionally.
  - No --name: try dir/container.scef; if absent, scan dir for single *.scef;
    if exactly one → use it; otherwise error.
"""

import pathlib
import pytest

from conftest import (
    DEFAULT_PASSWORD,
    DEFAULT_CONTAINER_SIZE,
    FAST_KDF_ARGS,
    create_container,
    list_container,
    extract_files,
    make_text_file,
    run_scef,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def create_container_with_name(
    container_dir: pathlib.Path,
    files: list,
    name: str,
    password: str = DEFAULT_PASSWORD,
    size: int = DEFAULT_CONTAINER_SIZE,
) -> None:
    """Run 'scef create ... --name <name>'."""
    args = ["create", "-c", str(container_dir), "--name", name]
    for f in files:
        args += ["-f", str(f)]
    args += ["-s", str(size)] + FAST_KDF_ARGS
    run_scef(args, password=password)


def list_with_name(
    container_dir: pathlib.Path,
    name: str,
    password: str = DEFAULT_PASSWORD,
    expect_success: bool = True,
) -> object:
    """Run 'scef list -c <dir> --name <name>'."""
    return run_scef(
        ["list", "-c", str(container_dir), "--name", name],
        password=password,
        expect_success=expect_success,
    )


def scef_files(container_dir: pathlib.Path) -> list:
    """Return sorted list of *.scef filenames in container_dir."""
    return sorted(p.name for p in container_dir.glob("*.scef"))


# ---------------------------------------------------------------------------
# Tests: create default naming
# ---------------------------------------------------------------------------

class TestDefaultCreateNaming:
    """No --name flag: containers are auto-numbered starting from container.scef."""

    def test_default_create_produces_container_scef(self, tmp_path):
        """First create without --name must produce container.scef."""
        cdir = tmp_path / "c"
        cdir.mkdir()
        src = make_text_file(tmp_path / "f.txt", "content")

        create_container(cdir, [src])

        assert (cdir / "container.scef").exists(), (
            "Default create must produce container.scef"
        )

    def test_second_create_without_name_does_not_overwrite_first(self, tmp_path):
        """
        Second create without --name must produce container_1.scef, not
        overwrite container.scef.
        """
        cdir = tmp_path / "c"
        cdir.mkdir()
        src_a = make_text_file(tmp_path / "a.txt", "container A content")
        src_b = make_text_file(tmp_path / "b.txt", "container B content")

        create_container(cdir, [src_a])
        create_container(cdir, [src_b])

        assert (cdir / "container.scef").exists(), (
            "container.scef must still exist after second create"
        )
        assert (cdir / "container_1.scef").exists(), (
            "Second create without --name must produce container_1.scef"
        )

        # Verify the first container was not overwritten.
        result_a = run_scef(
            ["list", "-c", str(cdir), "--name", "container.scef"],
            password=DEFAULT_PASSWORD,
        )
        assert "a.txt" in result_a.stdout, (
            "container.scef was overwritten by second create — a.txt not found"
        )

    def test_third_create_produces_container_2(self, tmp_path):
        """Third create without --name must produce container_2.scef."""
        cdir = tmp_path / "c"
        cdir.mkdir()
        src_a = make_text_file(tmp_path / "a.txt", "A")
        src_b = make_text_file(tmp_path / "b.txt", "B")
        src_c = make_text_file(tmp_path / "c.txt", "C")

        create_container(cdir, [src_a])
        create_container(cdir, [src_b])
        create_container(cdir, [src_c])

        assert (cdir / "container.scef").exists()
        assert (cdir / "container_1.scef").exists()
        assert (cdir / "container_2.scef").exists(), (
            "Third create without --name must produce container_2.scef"
        )


# ---------------------------------------------------------------------------
# Tests: explicit --name flag
# ---------------------------------------------------------------------------

class TestExplicitNameFlag:
    """--name flag allows custom container filenames."""

    def test_create_with_explicit_name(self, tmp_path):
        """--name custom.scef must produce dir/custom.scef."""
        cdir = tmp_path / "c"
        cdir.mkdir()
        src = make_text_file(tmp_path / "f.txt", "content")

        create_container_with_name(cdir, [src], "custom.scef")

        assert (cdir / "custom.scef").exists(), (
            "--name custom.scef must produce container at dir/custom.scef"
        )
        assert not (cdir / "container.scef").exists(), (
            "--name custom.scef must not also create container.scef"
        )

    def test_list_with_explicit_name_finds_correct_container(self, tmp_path):
        """
        Create two containers with different names; 'scef list --name' must
        access the correct one.
        """
        cdir = tmp_path / "c"
        cdir.mkdir()
        src_a = make_text_file(tmp_path / "a.txt", "content of A")
        src_b = make_text_file(tmp_path / "b.txt", "content of B")

        create_container_with_name(cdir, [src_a], "container.scef")
        create_container_with_name(cdir, [src_b], "other.scef")

        result = list_with_name(cdir, "other.scef")
        assert result.returncode == 0
        assert "b.txt" in result.stdout, (
            "'scef list --name other.scef' must list other.scef's contents"
        )
        assert "a.txt" not in result.stdout, (
            "'scef list --name other.scef' must not list container.scef's contents"
        )

    def test_name_with_forward_slash_rejected(self, tmp_path):
        """
        --name foo/bar.scef must be rejected: path separators are not allowed
        in container names (spec: filename only, no path separators).
        """
        cdir = tmp_path / "c"
        cdir.mkdir()
        src = make_text_file(tmp_path / "f.txt", "x")

        result = run_scef(
            [
                "create",
                "-c", str(cdir),
                "-f", str(src),
                "-s", str(DEFAULT_CONTAINER_SIZE),
                "--name", "foo/bar.scef",
            ] + FAST_KDF_ARGS,
            expect_success=False,
        )

        assert result.returncode != 0, (
            "--name with '/' separator must be rejected with non-zero exit"
        )

    def test_name_with_backslash_rejected(self, tmp_path):
        """
        --name foo\\bar.scef must be rejected: backslash is a path separator
        on Windows and is not allowed in container names.
        """
        cdir = tmp_path / "c"
        cdir.mkdir()
        src = make_text_file(tmp_path / "f.txt", "x")

        result = run_scef(
            [
                "create",
                "-c", str(cdir),
                "-f", str(src),
                "-s", str(DEFAULT_CONTAINER_SIZE),
                "--name", "foo\\bar.scef",
            ] + FAST_KDF_ARGS,
            expect_success=False,
        )

        assert result.returncode != 0, (
            "--name with '\\\\' separator must be rejected with non-zero exit"
        )


# ---------------------------------------------------------------------------
# Tests: open fallback behavior (list/extract without --name)
# ---------------------------------------------------------------------------

class TestOpenFallback:
    """
    Without --name, the open path (list/extract/add) follows:
      1. Try dir/container.scef — use if it exists.
      2. Scan dir for *.scef files; if exactly one → use it.
      3. Otherwise error.
    """

    def test_open_without_name_defaults_to_container_scef(self, tmp_path):
        """
        When container.scef exists, 'scef list' without --name must open it.
        """
        cdir = tmp_path / "c"
        cdir.mkdir()
        src = make_text_file(tmp_path / "main.txt", "main container")
        create_container_with_name(cdir, [src], "container.scef")

        result = list_container(cdir)
        assert result.returncode == 0
        assert "main.txt" in result.stdout, (
            "'scef list' without --name must open container.scef by default"
        )

    def test_open_without_name_finds_single_scef_when_no_default(self, tmp_path):
        """
        When container.scef does not exist but exactly one *.scef file is
        present, 'scef list' without --name must open that file.
        """
        cdir = tmp_path / "c"
        cdir.mkdir()
        src = make_text_file(tmp_path / "f.txt", "single scef fallback")
        create_container_with_name(cdir, [src], "backup.scef")

        # Verify container.scef does not exist.
        assert not (cdir / "container.scef").exists(), (
            "Test precondition: container.scef must not exist"
        )

        result = list_container(cdir)
        assert result.returncode == 0, (
            "'scef list' without --name must find backup.scef (single *.scef fallback).  "
            f"returncode={result.returncode}\nstderr: {result.stderr.strip()}"
        )
        assert "f.txt" in result.stdout, (
            "File 'f.txt' must appear in list output when backup.scef is auto-found"
        )

    def test_open_without_name_prefers_container_scef_over_single_other(self, tmp_path):
        """
        When both container.scef and backup.scef exist, 'scef list' without
        --name must open container.scef (priority rule 1: default name first).
        """
        cdir = tmp_path / "c"
        cdir.mkdir()
        src_main   = make_text_file(tmp_path / "main.txt", "main container")
        src_backup = make_text_file(tmp_path / "backup.txt", "backup container")

        create_container_with_name(cdir, [src_main], "container.scef")
        create_container_with_name(cdir, [src_backup], "backup.scef")

        result = list_container(cdir)
        assert result.returncode == 0
        assert "main.txt" in result.stdout, (
            "When container.scef exists, 'scef list' without --name must open it "
            "(not backup.scef)"
        )
        assert "backup.txt" not in result.stdout, (
            "'scef list' without --name must not open backup.scef when container.scef exists"
        )

    def test_open_without_name_fails_with_multiple_scef_files(self, tmp_path):
        """
        When multiple *.scef files exist and none is container.scef,
        'scef list' without --name must fail with a non-zero exit code
        (ambiguous — user must specify --name).
        """
        cdir = tmp_path / "c"
        cdir.mkdir()
        src_a = make_text_file(tmp_path / "a.txt", "A")
        src_b = make_text_file(tmp_path / "b.txt", "B")

        create_container_with_name(cdir, [src_a], "alpha.scef")
        create_container_with_name(cdir, [src_b], "beta.scef")

        # Neither is container.scef, so the single-fallback scan finds two files.
        assert not (cdir / "container.scef").exists()

        result = list_container(cdir, expect_success=False)
        assert result.returncode != 0, (
            "With multiple *.scef files and no container.scef, "
            "'scef list' without --name must fail (ambiguous)"
        )

    def test_open_without_name_fails_with_no_scef_files(self, tmp_path):
        """
        When no *.scef files exist, 'scef list' without --name must fail.
        """
        cdir = tmp_path / "c"
        cdir.mkdir()

        result = list_container(cdir, expect_success=False)
        assert result.returncode != 0, (
            "With no *.scef files, 'scef list' without --name must fail"
        )
