import pytest

from omnishield.sovereign import (
    SovereignError,
    binary,
    pairs,
    pipeline,
    status,
    verify_grant,
)


def test_bridge_is_available():
    assert binary().is_file()
    info = status()
    assert info["available"] is True
    assert "ca" in info["commands"]
    assert "verify" in info["commands"]


def test_pipeline_issues_and_verifies_a_grant():
    result = pipeline(rights="telemetry")
    assert result["ok"] is True
    assert result["stages"] == ["ca init", "ca init", "ca certify", "enroll", "host", "verify"]
    assert result["grant_bytes"] > 100
    assert "valid=true" in result["verify_stdout"]
    assert result["elapsed_ms"] > 0


def test_errors_are_refused():
    with pytest.raises(SovereignError):
        pipeline(rights="  ")
    with pytest.raises(SovereignError):
        verify_grant("not-hex", "also-not-hex")
    assert pairs("a=1\nb=2\n") == {"a": "1", "b": "2"}
