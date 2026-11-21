import json
import socket
import struct

import pytest

from omnishield.federation import (
    DeviceRegistry,
    FederationError,
    ReplayWindow,
    beacon_document,
    inventory,
    listening_ports,
    neighbours,
    open_message,
    parse_sntp,
    probe,
    seal_message,
    send_message,
    send_syslog,
    sntp_request,
    syslog_line,
    verify_beacon,
)
from omnishield.hybrid import HybridSigner, HybridVerifier, now_ms


def test_signed_message_round_trip_over_a_socket():
    alice = HybridSigner.generate()
    left, right = socket.socketpair()
    try:
        document = seal_message({"order": "lock the door"}, kind="command", signer=alice)
        send_message(left, document)
        received = open_message(
            json.loads(_read_frame(right)),
            verifier=HybridVerifier(alice.public_identity),
            replay=ReplayWindow(),
        )
    finally:
        left.close()
        right.close()
    assert received["kind"] == "command"
    assert received["payload"] == {"order": "lock the door"}
    assert received["sender"] == alice.public_identity.key_id.hex()


def _read_frame(connection):
    length = struct.unpack(">I", connection.recv(4))[0]
    body = b""
    while len(body) < length:
        body += connection.recv(length - len(body))
    return body


def test_tampering_and_wrong_keys_are_refused():
    alice = HybridSigner.generate()
    document = seal_message({"amount": 10}, kind="payment", signer=alice)
    document["message"]["payload"]["amount"] = 1000
    with pytest.raises(FederationError, match="signature"):
        open_message(document, verifier=HybridVerifier(alice.public_identity), replay=ReplayWindow())

    clean = seal_message({"amount": 10}, kind="payment", signer=alice)
    stranger = HybridSigner.generate()
    with pytest.raises(FederationError):
        open_message(clean, verifier=HybridVerifier(stranger.public_identity), replay=ReplayWindow())


def test_replay_and_stale_messages_are_refused():
    alice = HybridSigner.generate()
    verifier = HybridVerifier(alice.public_identity)
    document = seal_message({"x": 1}, kind="ping", signer=alice)
    replay = ReplayWindow()
    open_message(document, verifier=verifier, replay=replay)
    with pytest.raises(FederationError, match="replayed"):
        open_message(document, verifier=verifier, replay=replay)

    old = seal_message(
        {"x": 1}, kind="ping", signer=alice, now=now_ms() - 600_000, ttl_ms=900_000
    )
    with pytest.raises(FederationError, match="time window"):
        open_message(old, verifier=verifier, replay=ReplayWindow())

    expired = seal_message({"x": 1}, kind="ping", signer=alice, now=now_ms() - 600_000)
    with pytest.raises(FederationError, match="expired"):
        open_message(expired, verifier=verifier, replay=ReplayWindow())


def test_beacons_verify_and_pin_on_first_use(tmp_path):
    device = HybridSigner.generate()
    device_id = device.public_identity.key_id.hex()
    document = beacon_document(
        device_id, signer=device, capabilities=["camera", "lock"], port=9000
    )
    verified = verify_beacon(document)
    assert verified["device_id"] == device_id
    assert verified["capabilities"] == ["camera", "lock"]

    registry = DeviceRegistry(tmp_path / "devices.json")
    record = registry.pin(device_id, verified["identity"], capabilities=verified["capabilities"])
    assert record["key_id"] == device_id
    assert registry.lookup(device_id)["capabilities"] == ["camera", "lock"]

    impostor = HybridSigner.generate()
    with pytest.raises(FederationError, match="different key"):
        registry.pin(device_id, impostor.public_identity)

    reloaded = DeviceRegistry(tmp_path / "devices.json")
    assert reloaded.lookup(device_id)["key_id"] == device_id
    assert (tmp_path / "devices.json").stat().st_mode & 0o777 == 0o600


def test_beacon_edge_cases():
    device = HybridSigner.generate()
    other = HybridSigner.generate()
    wrong_id = beacon_document(
        other.public_identity.key_id.hex(), signer=device
    )
    with pytest.raises(FederationError, match="device id"):
        verify_beacon(wrong_id)

    expired = beacon_document(
        device.public_identity.key_id.hex(), signer=device, ttl_s=1, now=now_ms() - 60_000
    )
    with pytest.raises(FederationError, match="expired"):
        verify_beacon(expired)

    tampered = beacon_document(device.public_identity.key_id.hex(), signer=device)
    tampered["beacon"]["capabilities"] = ["root"]
    with pytest.raises(FederationError, match="signature"):
        verify_beacon(tampered)


def test_probe_reports_open_and_closed_ports():
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]
    try:
        assert probe("127.0.0.1", port)["open"] is True
    finally:
        listener.close()
    assert probe("127.0.0.1", port, timeout=0.2)["open"] is False


def test_neighbours_and_listening_ports_parse_real_formats(tmp_path):
    arp = tmp_path / "arp"
    arp.write_text(
        "IP address       HW type     Flags       HW address            Mask     Device\n"
        "192.168.1.1      0x1         0x2         aa:bb:cc:dd:ee:ff     *        wlan0\n"
        "192.168.1.9      0x1         0x0         00:00:00:00:00:00     *        wlan0\n"
    )
    table = neighbours(arp)
    assert table["available"] is True
    assert table["entries"][0]["mac"] == "aa:bb:cc:dd:ee:ff"
    assert table["entries"][1]["complete"] is False
    assert neighbours(tmp_path / "missing")["available"] is False

    tcp = tmp_path / "tcp"
    tcp.write_text(
        "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid\n"
        "   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000\n"
        "   1: 0100007F:0050 0100007F:9C40 01 00000000:00000000 00:00000000 00000000  1000\n"
    )
    ports = listening_ports(tcp)
    assert ports["ports"] == [{"port": 8080, "addresses": ["127.0.0.1"]}]
    assert listening_ports(tmp_path / "missing")["available"] is False

    combined = inventory(arp=arp, tcp=tcp)
    assert combined["neighbour_count"] == 2
    assert combined["listening_count"] == 1


def test_syslog_format_and_delivery():
    line = syslog_line("link down", severity="warning", app="omnishield")
    assert line.startswith("<12>1 ")
    assert line.endswith(" omnishield omnishield - - link down")
    assert syslog_line("x", severity="error").startswith("<11>1 ")
    with pytest.raises(FederationError):
        syslog_line("x", severity="panic")

    receiver = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    receiver.bind(("127.0.0.1", 0))
    receiver.settimeout(2.0)
    try:
        send_syslog(receiver.getsockname(), line)
        payload, _ = receiver.recvfrom(4096)
    finally:
        receiver.close()
    assert payload.decode("utf-8") == line


def test_sntp_packet_and_parser():
    request = sntp_request()
    assert len(request) == 48
    assert request[0] == 0x1B

    seconds = 2_208_988_800 + 1_700_000_000
    response = bytearray(48)
    response[40:44] = struct.pack(">I", seconds)
    response[44:48] = struct.pack(">I", 0)
    parsed = parse_sntp(bytes(response))
    assert parsed["unix"] == 1_700_000_000
    assert parsed["iso"] == "2023-11-14T22:13:20Z"

    with pytest.raises(FederationError):
        parse_sntp(b"short")
    with pytest.raises(FederationError):
        parse_sntp(bytes(48))
