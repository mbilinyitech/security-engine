import pytest

from omnishield.hybrid import HybridSigner
from omnishield.payments import Limits, PaymentError, PaymentService


class RecordingGateway:
    def __init__(self):
        self.charged = []

    def charge(self, intent):
        self.charged.append(intent)
        return f"rcpt-{len(self.charged)}"


@pytest.fixture
def service(tmp_path):
    requester = HybridSigner.generate()
    approver = HybridSigner.generate()
    gateway = RecordingGateway()
    payments = PaymentService(
        tmp_path / "ledger.jsonl",
        requester,
        limits=Limits(max_amount_cents=50_000),
        gateway=gateway,
    )
    return payments, requester, approver, gateway


def test_full_flow_moves_through_approval_and_writes_a_balanced_ledger(service):
    payments, _, approver, gateway = service
    intent = payments.create(12_500, "TZS", "Amina", memo="ushauri")
    approval = payments.approve(intent, approver, approver_name="human:amina")
    record = payments.settle(intent, approval, approver.public_identity)
    assert record["receipt"] == "rcpt-1"
    assert gateway.charged[0]["amount_cents"] == 12_500
    assert payments.balance() == {"Amina": 12_500, "cash": -12_500}
    assert sum(payments.balance().values()) == 0


def test_without_a_gateway_money_never_moves(tmp_path):
    requester = HybridSigner.generate()
    approver = HybridSigner.generate()
    payments = PaymentService(tmp_path / "ledger.jsonl", requester)
    intent = payments.create(1_000, "USD", "Watoa huduma")
    approval = payments.approve(intent, approver, approver_name="human:bob")
    with pytest.raises(PaymentError, match="refusing to move money"):
        payments.settle(intent, approval, approver.public_identity)
    assert payments.postings() == []


def test_an_approval_from_another_key_is_refused(service):
    payments, _, _, _ = service
    intent = payments.create(500, "USD", "X")
    other = HybridSigner.generate()
    approval = payments.approve(intent, other, approver_name="human:mallory")
    with pytest.raises(PaymentError):
        payments.settle(intent, approval, HybridSigner.generate().public_identity)


def test_the_requester_cannot_approve_its_own_payment(service):
    payments, requester, _, _ = service
    intent = payments.create(500, "USD", "X")
    with pytest.raises(PaymentError, match="own payment"):
        payments.approve(intent, requester, approver_name="me")


def test_the_ceiling_is_enforced(service):
    payments, _, _, _ = service
    with pytest.raises(PaymentError, match="ceiling"):
        payments.create(50_001, "USD", "X")
    with pytest.raises(PaymentError, match="positive"):
        payments.create(0, "USD", "X")
    with pytest.raises(PaymentError, match="currency"):
        payments.create(100, "XYZ", "X")


def test_settling_twice_is_refused(service):
    payments, _, approver, _ = service
    intent = payments.create(700, "KES", "X")
    approval = payments.approve(intent, approver, approver_name="human:amina")
    payments.settle(intent, approval, approver.public_identity)
    with pytest.raises(PaymentError, match="already settled"):
        payments.settle(intent, approval, approver.public_identity)


def test_an_approval_for_a_different_intent_is_refused(service):
    payments, _, approver, _ = service
    first = payments.create(700, "KES", "X")
    second = payments.create(800, "KES", "Y")
    approval = payments.approve(first, approver, approver_name="human:amina")
    with pytest.raises(PaymentError, match="different"):
        payments.settle(second, approval, approver.public_identity)
