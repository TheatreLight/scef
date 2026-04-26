import os
import re
import subprocess

from conftest import DEFAULT_CONTAINER_SIZE, SCEF_BIN, make_text_file


FAST_STRENGTH_KDF_ARGS = [
    "--kdf-m-cost", "64",
    "--kdf-t-cost", "1",
    "--kdf-parallelism", "1",
]


def _run_raw(args: list, stdin_text: str = "\n", timeout: int = 60,
             env=None) -> subprocess.CompletedProcess:
    child_env = os.environ.copy()
    if env:
        child_env.update(env)
    return subprocess.run(
        [str(SCEF_BIN)] + [str(a) for a in args],
        input=stdin_text,
        capture_output=True,
        text=True,
        timeout=timeout,
        env=child_env,
    )


def _create_args(container_dir, src, extra_args=None):
    args = ["create"]
    if extra_args:
        args += extra_args
    args += [
        "-c", str(container_dir),
        "-f", str(src),
        "-s", str(DEFAULT_CONTAINER_SIZE),
    ]
    args += FAST_STRENGTH_KDF_ARGS
    return args


def test_weak_password_warning_non_tty_without_yes_proceeds(tmp_path):
    src = make_text_file(tmp_path / "plain.txt", "hello\n")
    cdir = tmp_path / "container"
    cdir.mkdir()

    result = _run_raw(_create_args(cdir, src), stdin_text="password\n", timeout=120)

    assert result.returncode == 0, result.stderr
    assert (cdir / "container.scef").exists()
    assert "below recommended minimum" in result.stderr
    assert "Estimated offline crack time" in result.stderr


def test_weak_password_with_yes_flag_proceeds_without_prompt(tmp_path):
    src = make_text_file(tmp_path / "plain.txt", "hello\n")
    cdir = tmp_path / "container"
    cdir.mkdir()

    result = _run_raw(_create_args(cdir, src, ["-y"]), stdin_text="password\n", timeout=120)

    assert result.returncode == 0, result.stderr
    assert (cdir / "container.scef").exists()
    assert "below recommended minimum" in result.stderr
    assert "Proceed with this password?" not in result.stdout


def test_weak_password_prompt_accepts_y_when_forced(tmp_path):
    src = make_text_file(tmp_path / "plain.txt", "hello\n")
    cdir = tmp_path / "container"
    cdir.mkdir()

    result = _run_raw(
        _create_args(cdir, src),
        stdin_text="password\ny\n",
        timeout=120,
        env={"SCEF_FORCE_PROMPT": "1"},
    )

    assert result.returncode == 0, result.stderr
    assert (cdir / "container.scef").exists()
    assert "Proceed with this password?" in result.stderr


def test_weak_password_prompt_rejects_n_when_forced(tmp_path):
    src = make_text_file(tmp_path / "plain.txt", "hello\n")
    cdir = tmp_path / "container"
    cdir.mkdir()

    result = _run_raw(
        _create_args(cdir, src),
        stdin_text="password\nn\n",
        timeout=120,
        env={"SCEF_FORCE_PROMPT": "1"},
    )

    assert result.returncode == 1
    assert "Aborted due to weak password" in result.stderr
    assert not (cdir / "container.scef").exists()


def test_weak_password_prompt_rejects_empty_answer_when_forced(tmp_path):
    src = make_text_file(tmp_path / "plain.txt", "hello\n")
    cdir = tmp_path / "container"
    cdir.mkdir()

    result = _run_raw(
        _create_args(cdir, src),
        stdin_text="password\n\n",
        timeout=120,
        env={"SCEF_FORCE_PROMPT": "1"},
    )

    assert result.returncode == 1
    assert "Aborted due to weak password" in result.stderr
    assert not (cdir / "container.scef").exists()


def test_strong_password_has_no_strength_warning(tmp_path):
    src = make_text_file(tmp_path / "plain.txt", "hello\n")
    cdir = tmp_path / "container"
    cdir.mkdir()

    result = _run_raw(
        _create_args(cdir, src),
        stdin_text="a8K!92xQp$Lm7vRn4eY*hT\n",
        timeout=120,
    )

    assert result.returncode == 0, result.stderr
    assert (cdir / "container.scef").exists()
    assert "below recommended minimum" not in result.stderr
    assert "Weak password" not in result.stderr


def test_strength_only_prints_score_and_bits_without_creating_container(tmp_path):
    cdir = tmp_path / "container"
    cdir.mkdir()

    result = _run_raw(["--strength-only"], stdin_text="password\n")

    assert result.returncode == 0, result.stderr
    assert result.stderr == "" or "warning" not in result.stderr.lower()
    assert re.fullmatch(r"score=\d+ bits=\d+\.\d+\n", result.stdout) is not None, \
        f"unexpected stdout: {result.stdout!r}"
    assert not (cdir / "container.scef").exists()


def test_strength_only_is_position_independent_and_ignores_create_args(tmp_path):
    cdir = tmp_path / "container"
    cdir.mkdir()
    src = tmp_path / "ignored.txt"

    baseline = _run_raw(["--strength-only"], stdin_text="password\n")
    result = _run_raw(
        ["create", "--strength-only", "-c", str(cdir), "-f", str(src), "-s", "1"],
        stdin_text="password\n",
    )

    assert baseline.returncode == 0, baseline.stderr
    assert result.returncode == 0, result.stderr
    assert result.stderr == "" or "warning" not in result.stderr.lower()
    assert re.fullmatch(r"score=\d+ bits=\d+\.\d+\n", result.stdout) is not None, \
        f"unexpected stdout: {result.stdout!r}"
    assert result.stdout == baseline.stdout
    assert not (cdir / "container.scef").exists()
