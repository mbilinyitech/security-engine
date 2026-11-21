import pytest

from omnishield.hybrid import HybridSigner, HybridVerifier
from omnishield.synthesis import (
    SynthesisError,
    check_source,
    run_tool,
    synthesize,
    verify_tool,
)

SOURCE = "def run(payload):\n    return {'sum': payload['a'] + payload['b']}\n"


@pytest.fixture
def env(tmp_path):
    signer = HybridSigner.generate()
    return tmp_path, signer, HybridVerifier(signer.public_identity)


def test_synthesized_tool_runs_in_the_sandbox(env):
    root, signer, verifier = env
    document = synthesize("adder", SOURCE, signer, root)
    outcome = run_tool(document, verifier, root, {"a": 2, "b": 3})
    assert outcome["result"] == {"sum": 5}
    assert isinstance(outcome["network_isolated"], bool)
    assert outcome["limits"]["memory_mb"] == 256


def test_dangerous_sources_are_refused_before_signing(env):
    root, signer, _ = env
    for source in (
        "import os\n\ndef run(payload):\n    return os.getcwd()\n",
        "from subprocess import run as shell\n\ndef run(payload):\n    return shell(['id'])\n",
        "def run(payload):\n    return eval('1+1')\n",
        "def run(payload):\n    return payload.__class__\n",
        "def run(payload):\n    return open('/etc/passwd').read()\n",
    ):
        with pytest.raises(SynthesisError):
            check_source(source)
        with pytest.raises(SynthesisError):
            synthesize("bad", source, signer, root)


def test_a_tool_must_define_run(env):
    root, signer, _ = env
    with pytest.raises(SynthesisError, match="run"):
        synthesize("empty", "VALUE = 1\n", signer, root)


def test_names_are_restricted(env):
    root, signer, _ = env
    for name in ("UPPER", "with space", "1bad", "x"):
        with pytest.raises(SynthesisError):
            synthesize(name, SOURCE, signer, root)


def test_a_tampered_tool_is_refused(env):
    root, signer, verifier = env
    document = synthesize("adder", SOURCE, signer, root)
    (root / "tools" / "adder.py").write_text(
        "def run(payload):\n    return {'sum': 0}\n", encoding="utf-8"
    )
    with pytest.raises(SynthesisError, match="changed"):
        run_tool(document, verifier, root, {"a": 1, "b": 1})


def test_a_tool_signed_by_another_key_is_refused(env):
    root, signer, _ = env
    document = synthesize("adder", SOURCE, signer, root)
    other = HybridSigner.generate()
    with pytest.raises(SynthesisError, match="signature"):
        verify_tool(document, HybridVerifier(other.public_identity), root)


def test_an_endless_tool_is_killed(env):
    root, signer, verifier = env
    document = synthesize(
        "spin", "def run(payload):\n    while True:\n        pass\n", signer, root
    )
    with pytest.raises(SynthesisError, match="wall-clock"):
        run_tool(document, verifier, root, {}, timeout=1.0)
