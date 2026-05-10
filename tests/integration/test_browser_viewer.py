"""
Integration tests for BrowserViewer CLI behavior.

Verified behaviors
------------------
- Default `scef create` copies <exe_dir>/index.html next to the container.
- Existing destination index.html is overwritten by the default copy.
- Missing viewer source makes create fail after the container file is written.
- --no-browser-viewer skips the copy and succeeds even when the source is absent.
- Help text documents --no-browser-viewer.
"""

import contextlib
import pathlib
import uuid

from conftest import (
    DEFAULT_CONTAINER_SIZE,
    FAST_KDF_ARGS,
    make_text_file,
    run_scef,
)


def container_file(container_dir: pathlib.Path) -> pathlib.Path:
    return container_dir / "container.scef"


def browser_viewer_dest(container_dir: pathlib.Path) -> pathlib.Path:
    return container_dir / "index.html"


def browser_viewer_source(scef_bin: pathlib.Path) -> pathlib.Path:
    return pathlib.Path(scef_bin).parent / "index.html"


def run_create(container_dir: pathlib.Path,
               src: pathlib.Path,
               extra_args: list = None,
               expect_success: bool = True):
    args = [
        "create",
        "-c", str(container_dir),
        "-f", str(src),
        "-s", str(DEFAULT_CONTAINER_SIZE),
        "-y",
    ]
    if extra_args:
        args += extra_args
    args += FAST_KDF_ARGS
    return run_scef(args, expect_success=expect_success)


@contextlib.contextmanager
def with_browser_viewer_source(scef_bin: pathlib.Path, content: bytes):
    source = browser_viewer_source(scef_bin)
    original = source.read_bytes() if source.exists() else None
    source.write_bytes(content)
    try:
        yield source
    finally:
        if original is None:
            source.unlink(missing_ok=True)
        else:
            source.write_bytes(original)


@contextlib.contextmanager
def without_browser_viewer_source(scef_bin: pathlib.Path):
    source = browser_viewer_source(scef_bin)
    backup = source.with_name(f"index.html.{uuid.uuid4().hex}.bak")
    had_original = source.exists()
    if had_original:
        source.replace(backup)
    try:
        yield source
    finally:
        source.unlink(missing_ok=True)
        if had_original:
            backup.replace(source)


def test_browser_viewer_create_default_copies_index_html(tmp_path, scef_bin):
    cdir = tmp_path / "container"
    cdir.mkdir()
    src = make_text_file(tmp_path / "payload.txt", "payload")
    expected = b"<!doctype html><title>SCEF test viewer</title>\n"

    with with_browser_viewer_source(scef_bin, expected):
        run_create(cdir, src)

    assert browser_viewer_dest(cdir).read_bytes() == expected


def test_browser_viewer_create_default_overwrites_existing_index(tmp_path, scef_bin):
    cdir = tmp_path / "container"
    cdir.mkdir()
    src = make_text_file(tmp_path / "payload.txt", "payload")
    browser_viewer_dest(cdir).write_bytes(b"stale viewer")
    expected = b"<!doctype html><title>SCEF replacement viewer</title>\n"

    with with_browser_viewer_source(scef_bin, expected):
        run_create(cdir, src)

    assert browser_viewer_dest(cdir).read_bytes() == expected


def test_browser_viewer_create_missing_source_fails_and_keeps_container(tmp_path, scef_bin):
    cdir = tmp_path / "container"
    cdir.mkdir()
    src = make_text_file(tmp_path / "payload.txt", "payload")

    with without_browser_viewer_source(scef_bin):
        result = run_create(cdir, src, expect_success=False)

    assert result.returncode != 0
    assert "ERROR" in result.stderr
    assert "browser viewer copy failed" in result.stderr
    assert container_file(cdir).exists()


def test_browser_viewer_no_browser_viewer_missing_source_succeeds_without_touching_index(
    tmp_path,
    scef_bin,
):
    cdir = tmp_path / "container"
    cdir.mkdir()
    src = make_text_file(tmp_path / "payload.txt", "payload")
    preexisting_dest = b"preexisting destination viewer"
    browser_viewer_dest(cdir).write_bytes(preexisting_dest)

    with without_browser_viewer_source(scef_bin):
        result = run_create(cdir, src, extra_args=["--no-browser-viewer"])

    assert result.returncode == 0
    assert container_file(cdir).exists()
    assert browser_viewer_dest(cdir).read_bytes() == preexisting_dest


def test_browser_viewer_help_exposes_no_browser_viewer_flag():
    result = run_scef(["--help"])

    assert result.returncode == 0
    assert "--no-browser-viewer" in result.stdout
