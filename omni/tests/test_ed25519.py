import base64

import pytest

from omnishield.net import NetError, Node, envelope, keypair, sign, verify


def test_sign_and_verify_round_trip():
    keys = keypair()
    assert len(base64.b64decode(keys["private"])) == 32
    assert len(base64.b64decode(keys["public"])) == 32
    message = envelope("hello", "alpha", {"name": "alpha"}, private_key=keys["private"])
    assert message["pub"] == keys["public"]
    assert message["sig"]
    verify(message)
    verify(message, keys["public"])


def test_tampering_and_unsigned_messages_are_refused():
    keys = keypair()
    message = sign(envelope("chat", "alpha", {"text": "hello"}), keys["private"])
    tampered = dict(message)
    tampered["payload"] = {"text": "evil"}
    with pytest.raises(NetError):
        verify(tampered)
    with pytest.raises(NetError):
        verify({"v": 1, "type": "hello", "from": "a", "nonce": "n", "payload": {}})
    node = Node("beta", require_signature=True)
    with pytest.raises(NetError):
        node.handle({"v": 1, "type": "hello", "from": "a", "nonce": "n1", "payload": {}})
    node.handle(message)


def test_a_peer_cannot_change_its_key(tmp_path):
    from omnishield.knowledge import KnowledgeStore

    keys = keypair()
    other = keypair()
    node = Node("beta", store=KnowledgeStore.open(tmp_path / "k.jsonl"), require_signature=True)
    first = sign(envelope("hello", "alpha", {"n": 1}), keys["private"])
    node.handle(first)
    second = sign(envelope("hello", "alpha", {"n": 2}), other["private"])
    with pytest.raises(NetError):
        node.handle(second)
