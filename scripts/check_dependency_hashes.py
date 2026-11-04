"""Verify pinned installs and intentional hash failures in disposable directories.

Downloads public wheels; never reads the application environment or sends mail.
--docker also proves both application Dockerfiles reject a wrong dependency hash.
"""

import argparse
import hashlib
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def run(command: list[str], log: Path, *, reject: bool = False) -> None:
    result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=600)
    output = result.stdout + result.stderr
    log.write_text(output, encoding="utf-8")
    if reject:
        if result.returncode == 0 or "DO NOT MATCH THE HASHES" not in output:
            raise RuntimeError(f"Expected a hash mismatch, got another outcome; inspect {log}")
    elif result.returncode != 0:
        raise RuntimeError(f"Dependency verification failed; inspect {log}")


def check(work: Path, *, docker: bool) -> None:
    wheels = work / "wheels"
    wheels.mkdir()
    pip = [sys.executable, "-m", "pip", "--isolated", "--disable-pip-version-check"]
    locks = ["-r", str(ROOT / "requirements.lock"), "-r", str(ROOT / "requirements-test.lock")]
    run(
        pip
        + [
            "download",
            "--require-hashes",
            "--only-binary=:all:",
            "--no-cache-dir",
            "--index-url",
            "https://pypi.org/simple",
            "--dest",
            str(wheels),
            *locks,
        ],
        work / "download.log",
    )
    run(
        pip
        + [
            "install",
            "--require-hashes",
            "--only-binary=:all:",
            "--ignore-installed",
            "--no-index",
            "--find-links",
            str(wheels),
            "--target",
            str(work / "installed"),
            *locks,
        ],
        work / "install.log",
    )
    wheel = next(wheels.glob("six-*.whl"))
    digest = hashlib.sha256(wheel.read_bytes()).hexdigest()
    bad_lock = work / "wrong-hash.lock"
    bad_lock.write_text(f"six @ {wheel.as_uri()} --hash=sha256:{'0' * 64}\n", encoding="utf-8")
    install = pip + [
        "install",
        "--require-hashes",
        "--only-binary=:all:",
        "--no-index",
        "--ignore-installed",
        "--no-deps",
        "--target",
        str(work / "rejected"),
    ]
    run(install + ["-r", str(bad_lock)], work / "wrong-hash.log", reject=True)
    changed = work / "tampered" / wheel.name
    changed.parent.mkdir()
    raw = wheel.read_bytes()
    changed.write_bytes(raw[:-1] + bytes([raw[-1] ^ 1]))
    bad_lock.write_text(f"six @ {changed.as_uri()} --hash=sha256:{digest}\n", encoding="utf-8")
    run(install + ["-r", str(bad_lock)], work / "tampered-wheel.log", reject=True)
    if docker:
        if not shutil.which("docker"):
            raise RuntimeError("Docker is required for the requested image-build rejection drill")
        version = re.search(r"^six==([^\s]+)", (ROOT / "requirements.in").read_text(), re.M)[1]
        for label, path in [
            ("backend", ROOT / "Dockerfile"),
            ("pq", ROOT / "deploy/Dockerfile.pq"),
        ]:
            context = work / label
            context.mkdir()
            shutil.copyfile(path, context / "Dockerfile")
            (context / "requirements.lock").write_text(f"six=={version} --hash=sha256:{'0' * 64}\n")
            shutil.copyfile(ROOT / "requirements-test.lock", context / "requirements-test.lock")
            for directory in ["backend", "secure_mail", "scripts"]:
                (context / directory).mkdir()
                (context / directory / ".keep").touch()
            for filename in ["manage.py", "pyproject.toml"]:
                (context / filename).touch()
            run(
                ["docker", "build", "--no-cache", "--progress=plain", str(context)],
                work / f"{label}-hash-rejection.log",
                reject=True,
            )
    print(
        f"Verified full locked install, wrong hash and tampered-wheel rejection. Evidence: {work}"
    )
    if docker:
        print("Both application Dockerfiles rejected the incorrect dependency hash.")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--docker", action="store_true")
    args = parser.parse_args()
    runtime = ROOT / ".runtime"
    runtime.mkdir(exist_ok=True)
    check(Path(tempfile.mkdtemp(prefix="dependency-hashes-", dir=runtime)), docker=args.docker)


if __name__ == "__main__":
    main()
