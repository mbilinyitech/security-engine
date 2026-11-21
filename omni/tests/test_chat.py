import pytest

from omnishield.answer import answer
from omnishield.knowledge import KnowledgeStore
from omnishield.net import NetError, Node, envelope


def test_peer_answers_over_the_wire(tmp_path):
    store = KnowledgeStore.open(tmp_path / "k.jsonl")
    store.add("OmniNet frames are length prefixed JSON with a nonce.", source="chat")
    passages = [{"text": item["text"], "source": item["source"]} for item in store.items]

    def answerer(question: str) -> str:
        return answer(question, passages)["answer"]

    alpha = Node("alpha", store=store)
    beta = Node("beta", store=store, answerer=answerer)
    beta.start()
    try:
        request = envelope("chat", "alpha", {"text": "what are OmniNet frames"})
        reply = alpha.send("127.0.0.1", beta.port, request)
        assert reply["type"] == "chat"
        assert "length prefixed" in reply["payload"]["reply"]
        with pytest.raises(NetError):
            beta.handle(request)
    finally:
        beta.stop()


def test_empty_question_and_missing_answerer(tmp_path):
    store = KnowledgeStore.open(tmp_path / "k.jsonl")
    node = Node("solo", store=store)
    empty = node.handle(envelope("chat", "x", {"text": "  "}))
    assert empty["payload"]["error"] == "empty question"
    silent = node.handle(envelope("chat", "y", {"text": "hello"}))
    assert silent["payload"]["error"] == "no answerer"
