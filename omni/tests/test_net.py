import socket

import pytest

from omnishield.knowledge import KnowledgeStore
from omnishield.net import MAX_FRAME, NetError, Node, envelope, frame, validate


def test_hello_gossip_and_replay(tmp_path):
    alpha = Node("alpha", store=KnowledgeStore.open(tmp_path / "a.jsonl"))
    beta = Node("beta", store=KnowledgeStore.open(tmp_path / "b.jsonl"))
    alpha.start()
    port_b = beta.start()
    try:
        request = envelope("hello", "alpha", {"name": "alpha"})
        hello = alpha.send("127.0.0.1", port_b, request)
        assert hello["type"] == "hello" and hello["from"] == "beta"
        alpha.store.add("OmniNet uses length prefixed JSON frames.", source="alpha", title="net")
        sent = alpha.gossip([("127.0.0.1", port_b)])
        assert sent["ok"] == 1
        assert len(beta.store.items) == 1
        with pytest.raises(NetError):
            beta.handle(request)
    finally:
        alpha.stop()
        beta.stop()


def test_frames_are_bounded_and_validated():
    message = envelope("hello", "alpha", {"name": "alpha"})
    data = frame(message)
    assert int.from_bytes(data[:4], "big") == len(data) - 4
    with pytest.raises(NetError):
        validate({"v": 2, "type": "hello", "from": "a", "nonce": "n"})
    with pytest.raises(NetError):
        validate({"v": 1, "type": "explode", "from": "a", "nonce": "n"})
    with pytest.raises(NetError):
        validate({"v": 1, "type": "hello", "from": "", "nonce": "n"})
    with pytest.raises(NetError):
        envelope("explode", "a", {})
    with pytest.raises(NetError):
        frame(envelope("gossip", "a", {"items": ["x" * (MAX_FRAME + 10)]}))


def test_oversized_header_is_refused(tmp_path):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    port = server.getsockname()[1]
    from omnishield.net import read_frame

    with socket.create_connection(("127.0.0.1", port), timeout=2) as client:
        connection, _ = server.accept()
        with connection:
            client.sendall((MAX_FRAME + 1).to_bytes(4, "big"))
            with pytest.raises(NetError):
                read_frame(connection)
    server.close()
