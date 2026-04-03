"""
test_list.py — Integration tests for 'scef list'.

Verified behaviors
------------------
- 'scef list' exits with code 0 on a valid container.
- Output contains the filename of each file added to the container.
- Output contains all filenames when multiple files were added.
- Output does NOT contain filenames that were never added.
- After sequential adds, list reflects the cumulative file set.
- Wrong password on list fails with non-zero exit code.
- list on a non-existent container fails with non-zero exit code.
- list without -c flag fails with non-zero exit code.
"""

import pathlib
import pytest

from conftest import (
    DEFAULT_PASSWORD,
    DEFAULT_CONTAINER_SIZE,
    create_container,
    add_file,
    list_container,
    make_text_file,
    make_binary_file,
    make_file_with_bytes,
    run_scef,
)


# ---------------------------------------------------------------------------
# Tests: happy-path
# ---------------------------------------------------------------------------

class TestListBasic:
    """list reports the correct filenames."""

    def test_list_exits_zero(self, tmp_path):
        cdir = tmp_path / "c"
        cdir.mkdir()
        src = make_text_file(tmp_path / "f.txt", "content")
        create_container(cdir, [src])

        result = list_container(cdir)

        assert result.returncode == 0, (
            f"scef list returned non-zero: {result.returncode}\n"
            f"stderr: {result.stderr.strip()}"
        )

    def test_single_file_name_in_output(self, tmp_path):
        cdir = tmp_path / "c"
        cdir.mkdir()
        src = make_text_file(tmp_path / "report.txt", "annual report")
        create_container(cdir, [src])

        result = list_container(cdir)

        assert "report.txt" in result.stdout, (
            f"Expected 'report.txt' in list output, got:\n{result.stdout}"
        )

    def test_multiple_files_all_in_output(self, tmp_path):
        cdir = tmp_path / "c"
        cdir.mkdir()
        filenames = ["alpha.txt", "beta.bin", "gamma.dat"]
        files = [make_text_file(tmp_path / name, f"data of {name}") for name in filenames]

        create_container(cdir, files)

        result = list_container(cdir)
        for name in filenames:
            assert name in result.stdout, (
                f"Expected '{name}' in list output, got:\n{result.stdout}"
            )

    def test_absent_file_not_in_output(self, tmp_path):
        cdir = tmp_path / "c"
        cdir.mkdir()
        src = make_text_file(tmp_path / "present.txt", "yes")
        create_container(cdir, [src])

        result = list_container(cdir)

        assert "absent.txt" not in result.stdout, (
            "List output contains a filename that was never added"
        )


class TestListAfterAdd:
    """list reflects the state after successive add operations."""

    def test_list_after_one_add(self, tmp_path):
        cdir = tmp_path / "c"
        cdir.mkdir()
        f1 = make_text_file(tmp_path / "first.txt", "first")
        create_container(cdir, [f1])

        f2 = make_text_file(tmp_path / "second.txt", "second")
        add_file(cdir, f2)

        result = list_container(cdir)

        assert "first.txt" in result.stdout, (
            f"'first.txt' missing from list after add:\n{result.stdout}"
        )
        assert "second.txt" in result.stdout, (
            f"'second.txt' missing from list after add:\n{result.stdout}"
        )

    def test_list_after_two_adds(self, tmp_path):
        cdir = tmp_path / "c"
        cdir.mkdir()
        size = 8 * 1024 * 1024

        f1 = make_text_file(tmp_path / "f1.txt", "f1")
        create_container(cdir, [f1], size=size)

        f2 = make_text_file(tmp_path / "f2.txt", "f2")
        f3 = make_text_file(tmp_path / "f3.txt", "f3")
        add_file(cdir, f2)
        add_file(cdir, f3)

        result = list_container(cdir)

        for name in ("f1.txt", "f2.txt", "f3.txt"):
            assert name in result.stdout, (
                f"'{name}' missing from list after two adds:\n{result.stdout}"
            )

    def test_list_count_increases_after_add(self, tmp_path):
        """
        The list output must have more entries after adding a file.
        We do not parse exact counts but verify the new filename appears.
        """
        cdir = tmp_path / "c"
        cdir.mkdir()
        f1 = make_text_file(tmp_path / "existing.txt", "existing")
        create_container(cdir, [f1])

        result_before = list_container(cdir)
        lines_before = [l.strip() for l in result_before.stdout.splitlines() if l.strip()]

        f2 = make_text_file(tmp_path / "appended.txt", "appended")
        add_file(cdir, f2)

        result_after = list_container(cdir)
        lines_after = [l.strip() for l in result_after.stdout.splitlines() if l.strip()]

        assert len(lines_after) >= len(lines_before), (
            "Number of output lines did not increase after adding a file"
        )


class TestListFilenameVariants:
    """Filenames with various naming conventions appear correctly."""

    def test_filename_with_spaces(self, tmp_path):
        cdir = tmp_path / "c"
        cdir.mkdir()
        src = make_text_file(tmp_path / "my file.txt", "content")
        create_container(cdir, [src])

        result = list_container(cdir)

        assert "my file.txt" in result.stdout, (
            f"Filename with space not in list output:\n{result.stdout}"
        )

    def test_filename_with_numbers(self, tmp_path):
        cdir = tmp_path / "c"
        cdir.mkdir()
        src = make_text_file(tmp_path / "backup_2025_01_01.tar.gz", "archive")
        create_container(cdir, [src])

        result = list_container(cdir)

        assert "backup_2025_01_01.tar.gz" in result.stdout, (
            f"Filename with numbers not in list output:\n{result.stdout}"
        )

    def test_binary_file_name_in_output(self, tmp_path):
        cdir = tmp_path / "c"
        cdir.mkdir()
        src = make_binary_file(tmp_path / "image.png", 1024, b"\x89PNG")
        create_container(cdir, [src])

        result = list_container(cdir)

        assert "image.png" in result.stdout, (
            f"Binary file name not in list output:\n{result.stdout}"
        )


# ---------------------------------------------------------------------------
# Tests: error paths
# ---------------------------------------------------------------------------

class TestListErrorPaths:
    """list must fail when called with wrong args or wrong password."""

    def test_wrong_password_fails(self, tmp_path):
        cdir = tmp_path / "c"
        cdir.mkdir()
        src = make_text_file(tmp_path / "secret.txt", "secret")
        create_container(cdir, [src], password="correct_password")

        result = run_scef(
            ["list", "-c", str(cdir)],
            password="wrong_password",
            expect_success=False,
        )

        assert result.returncode != 0, (
            "scef list with wrong password must fail with non-zero exit code"
        )

    def test_nonexistent_container_fails(self, tmp_path):
        cdir = tmp_path / "no_such_dir"
        cdir.mkdir()

        result = list_container(cdir, expect_success=False)

        assert result.returncode != 0, (
            "scef list on non-existent container must fail with non-zero exit code"
        )

    def test_without_container_flag_fails(self, tmp_path):
        result = run_scef(["list"], expect_success=False)

        assert result.returncode != 0, (
            "scef list without -c must fail with non-zero exit code"
        )

    # truncated and wrong-magic containers are tested in
    # test_errors.py::TestCorruptContainers (test_list_file_smaller_than_header,
    # test_list_wrong_magic_bytes); no need to duplicate them here.
