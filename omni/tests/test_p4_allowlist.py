import random

import pytest

from omnishield.hybrid import HybridSigner, HybridVerifier, SigError
from omnishield.p4_allowlist import (
    AllowList,
    FrameFilter,
    InterArrivalGuard,
    NotAllowed,
    build_manifest,
    summarise,
    verify_manifest,
)
from omnishield.replay import ReplayCache


@pytest.fixture()
def workspace(tmp_path):
    root = tmp_path / "app"
    root.mkdir()
    (root / "app.py").write_text("VALUE = 41 + 1\n")
    (root / "data.bin").write_bytes(bytes(range(256)))
    return root


@pytest.fixture()
def signer():
    return HybridSigner.generate()


@pytest.fixture()
def manifest(workspace, signer):
    return build_manifest([workspace / "app.py", workspace / "data.bin"], signer, base_dir=workspace)


def test_manifest_roundtrip(manifest, signer):
    entries = verify_manifest(manifest, HybridVerifier(signer.public_identity))
    assert [entry.path for entry in entries] == ["app.py", "data.bin"]
    assert summarise(entries).startswith("2 artifact(s)")


def test_manifest_tamper_rejected(manifest, signer):
    manifest["payload"]["entries"][0]["sha256"] = "0" * 64
    with pytest.raises(SigError):
        verify_manifest(manifest, HybridVerifier(signer.public_identity), check_files=False)


def test_missing_artifact_rejected(workspace, manifest, signer):
    (workspace / "data.bin").unlink()
    with pytest.raises(NotAllowed, match="missing"):
        verify_manifest(manifest, HybridVerifier(signer.public_identity))


def test_modified_artifact_rejected(workspace, manifest, signer):
    (workspace / "app.py").write_text("VALUE = 0\n")
    with pytest.raises(NotAllowed, match="does not match"):
        verify_manifest(manifest, HybridVerifier(signer.public_identity))


def test_unlisted_artifact_rejected(workspace, manifest, signer):
    (workspace / "evil.py").write_text("print('x')\n")
    allow = AllowList(manifest, HybridVerifier(signer.public_identity))
    with pytest.raises(NotAllowed, match="not in the signed allow-list"):
        allow.verify_path("evil.py")


def test_allow_listed_module_loads(manifest, signer):
    allow = AllowList(manifest, HybridVerifier(signer.public_identity))
    assert allow.load_module("app.py").VALUE == 42


def test_artifact_outside_base_dir_rejected(workspace, signer, tmp_path):
    outside = tmp_path / "outside.txt"
    outside.write_text("x")
    with pytest.raises(NotAllowed, match="outside base directory"):
        build_manifest([outside], signer, base_dir=workspace)


def test_bot_cadence_flagged():
    guard = InterArrivalGuard()
    decisions = [guard.observe(index * 100) for index in range(12)]
    assert decisions[-1].allow is False
    assert "machine-regular" in decisions[-1].reason


def test_human_cadence_allowed():
    guard = InterArrivalGuard()
    rng = random.Random(11)
    clock = 0
    decision = None
    for _ in range(20):
        clock += rng.randint(20, 400)
        decision = guard.observe(clock)
    assert decision is not None and decision.allow is True


def test_high_rate_flagged():
    guard = InterArrivalGuard()
    decisions = [guard.observe(index) for index in range(12)]
    assert decisions[-1].allow is False
    assert "rate" in decisions[-1].reason


def test_frame_filter_accepts_signed_and_rejects_replay(signer):
    filt = FrameFilter(HybridVerifier(signer.public_identity), replay=ReplayCache())
    envelope = signer.sign(b"frame", domain="omnishield.p4.frame")
    assert filt.accept(envelope, b"frame") == b"frame"
    with pytest.raises(SigError):
        filt.accept(envelope, b"frame")


def test_frame_filter_rejects_wrong_domain(signer):
    filt = FrameFilter(HybridVerifier(signer.public_identity))
    envelope = signer.sign(b"frame", domain="something-else")
    with pytest.raises(SigError):
        filt.accept(envelope, b"frame")


def test_iter_artifacts_skips_build_junk(tmp_path):
    from omnishield.p4_allowlist import iter_artifacts

    (tmp_path / "keep.py").write_text("x")
    cache = tmp_path / "__pycache__"
    cache.mkdir()
    (cache / "keep.cpython-313.pyc").write_bytes(b"x")
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "config").write_text("x")
    assert [path.name for path in iter_artifacts(tmp_path)] == ["keep.py"]
