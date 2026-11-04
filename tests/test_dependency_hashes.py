import io
import json
import re
from pathlib import Path

import pytest

from scripts import lock_dependency_hashes as locks


def response(artifacts, version="1.2.3"):
    return io.BytesIO(json.dumps({"info": {"version": version}, "urls": artifacts}).encode())


def artifact(digest, *, kind="bdist_wheel", yanked=False):
    return {"digests": {"sha256": digest}, "packagetype": kind, "yanked": yanked}


def test_lock_generation_accepts_only_non_yanked_wheels(monkeypatch):
    monkeypatch.setattr(
        locks.urllib.request,
        "urlopen",
        lambda *args, **kwargs: response(
            [
                artifact("a" * 64),
                artifact("a" * 64),
                artifact("b" * 64),
                artifact("c" * 64, kind="sdist"),
                artifact("d" * 64, yanked=True),
            ]
        ),
    )
    assert locks.hashes("example==1.2.3") == ["a" * 64, "b" * 64]


@pytest.mark.parametrize("artifacts", [[], [artifact("bad")], [artifact("a" * 64, yanked=True)]])
def test_missing_or_invalid_release_hashes_fail_closed(monkeypatch, artifacts):
    monkeypatch.setattr(locks.urllib.request, "urlopen", lambda *a, **kw: response(artifacts))
    with pytest.raises(ValueError, match="hashes"):
        locks.hashes("example==1.2.3")


def test_release_version_must_match_requested_pin(monkeypatch):
    monkeypatch.setattr(
        locks.urllib.request,
        "urlopen",
        lambda *a, **kw: response([artifact("a" * 64)], version="9.9.9"),
    )
    with pytest.raises(ValueError, match="Unexpected release"):
        locks.hashes("example==1.2.3")


def test_every_checked_in_pin_has_hashes_and_preserves_version():
    root = Path(__file__).resolve().parents[1]
    for name in ["requirements", "requirements-test"]:
        source = (root / f"{name}.in").read_text().splitlines()
        expected = [line for line in source if line and not line.startswith("#")]
        content = (root / f"{name}.lock").read_text().replace("\\\n", " ")
        actual = []
        for line in content.splitlines():
            if not line or line.startswith("#"):
                continue
            pin, *hashes = line.split()
            actual.append(pin)
            assert hashes and all(re.fullmatch(r"--hash=sha256:[0-9a-f]{64}", h) for h in hashes)
        assert actual == expected
