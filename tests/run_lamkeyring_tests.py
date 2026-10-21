#!/usr/bin/env python3
"""Compile and run the @lam/keyring package tests in an isolated extlibs tree."""

from __future__ import annotations

import argparse
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


LIB_ROOT = Path(__file__).resolve().parents[1]
COMPILER = "lamc"
MIN_COMPILER_VERSION = (3, 0, 0)
MAX_COMPILER_VERSION = (4, 0, 0)  # exclusive, matches lamlib.toml ">=3.0, <4"
PACKAGE_PATH = Path("@lam") / "keyring"
VERSION_PATTERN = re.compile(r"(?:lamc\s+)?v?(\d+)\.(\d+)\.(\d+)(?:[-+].*)?")


def _run(command: list[str], *, cwd: Path, timeout: int) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        cwd=cwd,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )


def _check_compiler() -> bool:
    try:
        proc = _run([COMPILER, "version"], cwd=LIB_ROOT, timeout=10)
    except FileNotFoundError:
        print(f"Error: {COMPILER} is not installed or is not on PATH.", file=sys.stderr)
        return False
    except subprocess.TimeoutExpired:
        print(f"Error: {COMPILER} version check timed out.", file=sys.stderr)
        return False
    except OSError as exc:
        print(f"Error: unable to run {COMPILER}: {exc}", file=sys.stderr)
        return False

    if proc.returncode != 0:
        detail = proc.stderr.strip() or proc.stdout.strip() or f"exit status {proc.returncode}"
        print(f"Error: unable to check {COMPILER} version: {detail}", file=sys.stderr)
        return False

    version_text = proc.stdout.strip()
    match = VERSION_PATTERN.fullmatch(version_text)
    if not match:
        print(f"Error: {COMPILER} returned an invalid version: {version_text!r}.", file=sys.stderr)
        return False

    version = tuple(int(part) for part in match.groups())
    if version < MIN_COMPILER_VERSION:
        required = ".".join(str(part) for part in MIN_COMPILER_VERSION)
        print(
            f"Error: {COMPILER} {version_text} is incompatible; version >= {required} is required.",
            file=sys.stderr,
        )
        return False
    if version >= MAX_COMPILER_VERSION:
        limit = ".".join(str(part) for part in MAX_COMPILER_VERSION)
        print(
            f"Error: {COMPILER} {version_text} is incompatible; version < {limit} is required.",
            file=sys.stderr,
        )
        return False
    return True


def _expectations(source: str) -> list[str]:
    return [
        match.group(1).strip()
        for line in source.splitlines()
        if (match := re.match(r"^\s*#\s*expect:\s*(.*)$", line))
    ]


def _stage_package(extlibs: Path) -> None:
    destination = extlibs / PACKAGE_PATH
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(
        LIB_ROOT,
        destination,
        ignore=shutil.ignore_patterns(
            ".git",
            "build",
            "extlibs",
            "*.lamc-cache",
            "__pycache__",
            "*.pyc",
        ),
    )


def _process_failure(label: str, proc: subprocess.CompletedProcess[str]) -> str:
    details = [f"{label} ({proc.returncode})"]
    if proc.stdout.strip():
        details.append("stdout:\n" + proc.stdout.rstrip())
    if proc.stderr.strip():
        details.append("stderr:\n" + proc.stderr.rstrip())
    return "\n".join(details)


def _run_case(path: Path, extra_extlibs: list[Path]) -> tuple[bool, str]:
    expected = _expectations(path.read_text(encoding="utf-8"))
    if not expected:
        return False, "TEST ERROR: no '# expect:' lines found"

    with tempfile.TemporaryDirectory(prefix="lamkeyring_test_") as tmp:
        root = Path(tmp)
        extlibs = root / "extlibs"
        _stage_package(extlibs)
        binary = root / "test_binary"
        command = [
            COMPILER,
            str(path),
            "--extlibs",
            str(extlibs),
            *[arg for extra in extra_extlibs for arg in ("--extlibs", str(extra))],
            "--no-cache",
            "-o",
            str(binary),
        ]
        try:
            compile_proc = _run(command, cwd=root, timeout=240)
        except subprocess.TimeoutExpired:
            return False, "COMPILE FAIL: timed out after 240 seconds"
        except OSError as exc:
            return False, f"COMPILE FAIL: unable to run {COMPILER}: {exc}"
        if compile_proc.returncode != 0:
            return False, _process_failure("COMPILE FAIL", compile_proc)

        try:
            run_proc = _run([str(binary)], cwd=root, timeout=60)
        except subprocess.TimeoutExpired:
            return False, "RUN FAIL: timed out after 60 seconds"
        except OSError as exc:
            return False, f"RUN FAIL: unable to execute test binary: {exc}"
        if run_proc.returncode != 0:
            return False, _process_failure("RUN FAIL", run_proc)

        actual = run_proc.stdout.rstrip("\n")
        expected_text = "\n".join(expected)
        if actual != expected_text:
            return (
                False,
                "OUTPUT MISMATCH:\n"
                f"  expected: {expected_text!r}\n"
                f"  actual:   {actual!r}"
                + (f"\n  stderr:   {run_proc.stderr.rstrip()!r}" if run_proc.stderr else ""),
            )
        return True, "ok"


def main() -> int:
    parser = argparse.ArgumentParser(description="@lam/keyring package tests")
    parser.add_argument("--verbose", "-v", action="store_true", help="show full failure details")
    parser.add_argument("names", nargs="*", help="only run tests whose file name contains one of these")
    parser.add_argument(
        "--mft",
        metavar="DIR",
        type=Path,
        help="also run tests/interop/ against a managed-file-transfer checkout (its extlibs/ and lib/)",
    )
    args = parser.parse_args()

    if not _check_compiler():
        return 1

    cases = sorted((LIB_ROOT / "tests").glob("test_*.lam"))
    extra_extlibs: list[Path] = []
    if args.mft is not None:
        mft = args.mft.resolve()
        if not (mft / "lib" / "mft" / "security.lam").is_file():
            print(f"Error: {mft} is not a managed-file-transfer checkout.", file=sys.stderr)
            return 1
        extra_extlibs = [mft / "extlibs", mft / "lib"]
        cases += sorted((LIB_ROOT / "tests" / "interop").glob("test_*.lam"))
    if args.names:
        cases = [case for case in cases if any(name in case.name for name in args.names)]
    if not cases:
        print("Error: no @lam/keyring test cases found.", file=sys.stderr)
        return 1

    failures: list[tuple[Path, str]] = []
    print(f"Running {len(cases)} @lam/keyring test(s)...\n")
    for case in cases:
        ok, message = _run_case(case, extra_extlibs)
        relative = case.relative_to(LIB_ROOT)
        print(f"  {'PASS' if ok else 'FAIL'}  {relative}")
        if not ok:
            failures.append((relative, message))
            if args.verbose:
                for line in message.splitlines():
                    print(f"        {line}")

    passed = len(cases) - len(failures)
    print(f"\n@lam/keyring results: {passed} passed, {len(failures)} failed, {len(cases)} total")
    if failures and not args.verbose:
        print("Re-run with --verbose for failure details.")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
