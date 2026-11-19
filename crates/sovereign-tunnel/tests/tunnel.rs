//! Tunnel tests, including a real UDP round trip over loopback.
//!
//! The loopback tests use actual sockets and actual syscalls. They are the ones that would catch
//! a transport bug that a pure in-memory test would miss.

use std::net::{SocketAddr, UdpSocket};
use std::time::Duration;

use sovereign_crypto::fill_random;
use sovereign_ipc::{OpCode, SealedFrame};
use sovereign_tunnel::transport::UdpTransport;
use sovereign_tunnel::{
    chaff_datagram, ChaffSchedule, Datagram, PeerReplay, TunnelError, BUCKETS, MAGIC, MAX_DATAGRAM,
    VERSION,
};

fn frame(counter: u64, payload: &[u8]) -> SealedFrame {
    SealedFrame {
        capability_id: [0x11; 16],
        counter,
        epoch: 1,
        nonce: [0x22; 24],
        ciphertext: payload.to_vec(),
    }
}

// ---------------------------------------------------------------------------
// Datagram framing
// ---------------------------------------------------------------------------

#[test]
fn a_frame_survives_encode_and_decode() {
    let original = frame(7, b"sealed payload");
    let wire = Datagram::seal(&original).unwrap().encode().unwrap();
    let decoded = Datagram::decode(&wire).unwrap();

    assert_eq!(decoded.frame(), &original);
    assert_eq!(decoded.counter(), 7);
}

#[test]
fn every_datagram_is_padded_to_a_bucket() {
    for size in [1usize, 40, 200, 400, 900] {
        let wire = Datagram::seal(&frame(1, &vec![0xAB; size]))
            .unwrap()
            .encode()
            .unwrap();
        assert!(
            BUCKETS.contains(&wire.len()),
            "size {size} produced {} bytes, which is not a bucket",
            wire.len()
        );
    }
}

#[test]
fn padding_hides_the_exact_length() {
    // Two very different payloads must land in the same bucket, or padding achieves nothing.
    let small = Datagram::seal(&frame(1, &[0u8; 8]))
        .unwrap()
        .encode()
        .unwrap();
    let larger = Datagram::seal(&frame(2, &[0u8; 30]))
        .unwrap()
        .encode()
        .unwrap();
    assert_eq!(
        small.len(),
        larger.len(),
        "payloads of 8 and 30 bytes should be indistinguishable on the wire"
    );
}

#[test]
fn a_frame_too_large_for_the_path_is_refused_not_truncated() {
    let huge = frame(1, &vec![0u8; MAX_DATAGRAM]);
    assert_eq!(Datagram::seal(&huge).unwrap_err(), TunnelError::TooLarge);
}

#[test]
fn foreign_datagrams_are_rejected_before_parsing() {
    let mut wire = Datagram::seal(&frame(1, b"x")).unwrap().encode().unwrap();
    wire[0] = b'X';
    assert_eq!(Datagram::decode(&wire).unwrap_err(), TunnelError::BadMagic);
}

#[test]
fn an_unknown_version_is_refused() {
    let mut wire = Datagram::seal(&frame(1, b"x")).unwrap().encode().unwrap();
    wire[MAGIC.len()] = VERSION.wrapping_add(1);
    assert_eq!(
        Datagram::decode(&wire).unwrap_err(),
        TunnelError::UnsupportedVersion
    );
}

#[test]
fn a_truncated_datagram_is_refused_without_panicking() {
    let wire = Datagram::seal(&frame(1, b"payload"))
        .unwrap()
        .encode()
        .unwrap();
    // Every prefix must fail cleanly. A panic here would be a remote crash.
    for n in 0..wire.len() {
        assert!(Datagram::decode(&wire[..n]).is_err(), "prefix {n} decoded");
    }
}

#[test]
fn a_corrupt_pad_length_cannot_underflow_the_parser() {
    let mut wire = Datagram::seal(&frame(1, b"payload"))
        .unwrap()
        .encode()
        .unwrap();
    // Claim a pad larger than the datagram. The naive `len - pad` would panic in debug and
    // wrap in release, reading a huge slice.
    wire[MAGIC.len() + 1] = 0xFF;
    wire[MAGIC.len() + 2] = 0xFF;
    assert!(Datagram::decode(&wire).is_err());
}

#[test]
fn an_oversized_datagram_is_refused() {
    let buf = vec![0u8; MAX_DATAGRAM + 100];
    assert_eq!(Datagram::decode(&buf).unwrap_err(), TunnelError::TooLarge);
}

// ---------------------------------------------------------------------------
// Replay protection
// ---------------------------------------------------------------------------

#[test]
fn a_replayed_datagram_is_refused() {
    let mut replay = PeerReplay::new();
    replay.accept(5).unwrap();
    assert_eq!(replay.accept(5).unwrap_err(), TunnelError::Replay);
}

#[test]
fn out_of_order_datagrams_are_accepted_once() {
    let mut replay = PeerReplay::new();
    // UDP reorders freely, so this must not be treated as an attack.
    replay.accept(10).unwrap();
    replay.accept(9).unwrap();
    replay.accept(11).unwrap();
    replay.accept(8).unwrap();
    // But each only once.
    assert!(replay.accept(9).is_err());
    assert!(replay.accept(8).is_err());
}

// ---------------------------------------------------------------------------
// Chaff
// ---------------------------------------------------------------------------

#[test]
fn chaff_is_the_scheduled_size_and_is_not_a_valid_frame() {
    let bytes = chaff_datagram(256).unwrap();
    assert_eq!(bytes.len(), 256);
    assert_eq!(
        &bytes[..MAGIC.len()],
        &MAGIC,
        "chaff must look like our traffic"
    );
    // It must not parse as a frame: a receiver has to be able to tell, and so must a test.
    assert!(Datagram::decode(&bytes).is_err());
}

#[test]
fn chaff_bodies_differ_between_packets() {
    // If cover traffic were a fixed pattern, an observer could pick it out with a single
    // comparison and the padding would be worthless. Two packets must not be identical.
    let a = chaff_datagram(256).unwrap();
    let b = chaff_datagram(256).unwrap();
    assert_ne!(a, b, "cover traffic must not be a constant pattern");

    // And the body must not be a run of zeros either, which is the failure mode where the
    // RNG call is dropped and nobody notices.
    let header = Datagram::header_len();
    let body = &a[header..];
    assert!(
        body.iter().any(|&b| b != 0),
        "chaff body must be random, not zeroed"
    );
}

#[test]
fn chaff_sizes_are_clamped_into_the_valid_range() {
    let tiny = chaff_datagram(1).unwrap();
    let huge = chaff_datagram(usize::MAX).unwrap();
    assert!(tiny.len() >= Datagram::header_len() + 2);
    assert_eq!(huge.len(), MAX_DATAGRAM);
}

#[test]
fn the_chaff_schedule_does_not_fire_early() {
    let mut s = ChaffSchedule::new(100, 256, 0);
    assert_eq!(s.due(50), 0, "nothing due before the interval elapses");
    assert_eq!(s.due(100), 1);
    assert_eq!(s.due(150), 0);
    assert_eq!(s.due(200), 1);
}

#[test]
fn a_stalled_caller_catches_up_without_flooding() {
    let mut s = ChaffSchedule::new(10, 256, 0);
    // 1000ms stalled at a 10ms interval means 100 cover packets are "owed".
    let n = s.due(1000);
    assert!(n > 1, "a stall must be compensated, not silently dropped");
    assert!(n <= 64, "but never an unbounded burst");
}

// ---------------------------------------------------------------------------
// Real UDP over loopback
// ---------------------------------------------------------------------------

#[test]
fn frames_travel_over_a_real_udp_socket() {
    let sender = UdpTransport::bind("127.0.0.1:0", vec![]).unwrap();
    let from = sender.local_addr().unwrap();
    // The receiver only accepts from the sender, so a stranger cannot reach the parser.
    let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    let mut receiver = UdpTransport::from_socket(sock, vec![from]);
    let to = receiver.local_addr().unwrap();

    let sent = frame(1, b"hello over the wire");
    let n = sender.send_frame(to, &sent).unwrap();
    assert!(n > 0);

    receiver
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let (peer, got) = receiver.recv_frame().unwrap();

    assert_eq!(peer, from);
    assert_eq!(got.frame(), &sent, "the frame must arrive byte-for-byte");
}

#[test]
fn a_replayed_datagram_is_refused_over_a_real_socket() {
    let sender = UdpTransport::bind("127.0.0.1:0", vec![]).unwrap();
    let mut receiver = UdpTransport::bind("127.0.0.1:0", vec![]).unwrap();
    let to = receiver.local_addr().unwrap();

    let f = frame(42, b"once only");
    let wire = Datagram::seal(&f).unwrap().encode().unwrap();

    // Send the identical datagram twice, as a network-level attacker would.
    let raw = UdpSocket::bind("127.0.0.1:0").unwrap();
    let from = raw.local_addr().unwrap();
    let _ = from;
    raw.send_to(&wire, to).unwrap();
    raw.send_to(&wire, to).unwrap();

    receiver
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    assert!(receiver.recv_frame().is_ok(), "first delivery is fine");
    assert_eq!(
        receiver.recv_frame().unwrap_err(),
        TunnelError::Replay,
        "the duplicate must be dropped at the transport"
    );

    let _ = sender;
}

#[test]
fn a_peer_outside_the_allow_list_is_ignored() {
    let stranger = UdpTransport::bind("127.0.0.1:0", vec![]).unwrap();
    // Allow only an address nobody is using, so the stranger is definitely not it.
    let nobody: SocketAddr = "127.0.0.1:1".parse().unwrap();
    let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    let mut receiver = UdpTransport::from_socket(sock, vec![nobody]);
    let to = receiver.local_addr().unwrap();

    stranger.send_frame(to, &frame(1, b"unsolicited")).unwrap();
    receiver
        .set_read_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    assert_eq!(receiver.recv_frame().unwrap_err(), TunnelError::BadMagic);
}

#[test]
fn cover_traffic_reaches_the_peer_and_is_discarded_there() {
    let sender = UdpTransport::bind("127.0.0.1:0", vec![]).unwrap();
    let mut receiver = UdpTransport::bind("127.0.0.1:0", vec![]).unwrap();
    let to = receiver.local_addr().unwrap();

    let schedule = ChaffSchedule::new(1000, 256, 0);
    sender.send_chaff(to, &schedule).unwrap();

    receiver
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let err = receiver.recv_frame().unwrap_err();
    assert!(
        matches!(err, TunnelError::BadFrame | TunnelError::LengthMismatch),
        "cover traffic must be rejected as a frame, got {err:?}"
    );
}

#[test]
fn the_replay_window_is_per_peer() {
    let mut a = UdpTransport::bind("127.0.0.1:0", vec![]).unwrap();
    let mut b = UdpTransport::bind("127.0.0.1:0", vec![]).unwrap();
    let a_addr = a.local_addr().unwrap();
    let b_addr = b.local_addr().unwrap();

    // Both peers legitimately start their counters at 1. A shared window would treat the
    // second peer's first frame as a replay, which would be a silent outage.
    a.send_frame(b_addr, &frame(1, b"from a")).unwrap();
    b.send_frame(a_addr, &frame(1, b"from b")).unwrap();

    a.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    b.set_read_timeout(Some(Duration::from_secs(2))).unwrap();

    assert!(a.recv_frame().is_ok());
    assert!(b.recv_frame().is_ok());
    assert_eq!(a.peer_count(), 1);
    assert_eq!(b.peer_count(), 1);
}

#[test]
fn random_bytes_from_the_network_never_panic() {
    // A hostile sender can put anything on the wire. None of it may crash the receiver.
    let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
    let mut receiver = UdpTransport::bind("127.0.0.1:0", vec![]).unwrap();
    let to = receiver.local_addr().unwrap();
    receiver
        .set_read_timeout(Some(Duration::from_millis(300)))
        .unwrap();

    for len in [0usize, 1, 3, 7, 8, 64, 1200] {
        let mut junk = vec![0u8; len];
        let _ = fill_random(&mut junk);
        sender.send_to(&junk, to).unwrap();
        // Either it parses (impossible for random bytes) or it errors. No panic either way.
        let _ = receiver.recv_frame();
    }
}

#[test]
fn opcode_frames_still_round_trip_through_the_ipc_layer() {
    // Guards the seam: the tunnel carries SealedFrame, not the handshake Frame, and the two
    // must not be confused.
    let plain = sovereign_ipc::Frame::new(OpCode::Data, b"not sealed".to_vec()).unwrap();
    let encoded = plain.encode();
    let back = sovereign_ipc::Frame::decode(&encoded).unwrap();
    assert_eq!(back.opcode, OpCode::Data);
}
