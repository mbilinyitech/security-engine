//! Transport to the kernel driver.
//!
//! Two implementations share one trait so the handshake and sealing logic can be tested against
//! a mock without a loaded module:
//!
//! * [`StreamLink`] speaks the real [`sovereign_ipc`] frame protocol over any `Read + Write`,
//!   which on Linux is a character device exposed by the driver;
//! * [`MockKernel`] is an in-memory peer that enforces the same invariants, so the tests below
//!   exercise the real bridge code path rather than a stub.
//!
//! The link is treated as untrusted. It can drop, reorder, or lie. Every value that arrives
//! from it is re-validated by the caller; the link never gets to assert that a capability is
//! valid, only to carry bytes.

use std::io::{Read, Write};

use sovereign_crypto::HybridVerifyingKey;
use sovereign_ipc::{Frame, IpcError, OpCode};

use crate::handshake::{CapabilityGrant, HandshakeError};

/// A bidirectional byte channel to the kernel.
pub trait KernelLink {
    fn send(&mut self, frame: &Frame) -> Result<(), IpcError>;
    fn recv(&mut self) -> Result<Frame, IpcError>;
}

/// Real transport: length-prefixed frames over a character device or socket.
pub struct StreamLink<S: Read + Write> {
    stream: S,
}

impl<S: Read + Write> StreamLink<S> {
    pub fn new(stream: S) -> Self {
        Self { stream }
    }

    pub fn into_inner(self) -> S {
        self.stream
    }
}

impl<S: Read + Write> KernelLink for StreamLink<S> {
    fn send(&mut self, frame: &Frame) -> Result<(), IpcError> {
        sovereign_ipc::write_frame(&mut self.stream, frame)
    }

    fn recv(&mut self) -> Result<Frame, IpcError> {
        sovereign_ipc::read_frame(&mut self.stream)
    }
}

/// What the mock kernel remembers about a session, mirroring the driver's own state.
#[derive(Debug)]
pub struct MockKernel {
    root: HybridVerifyingKey,
    /// Pending outbound frame produced by `send` for the test to inspect.
    inbox: Vec<Frame>,
    /// Frames the mock will hand back on `recv`.
    outbox: Vec<Frame>,
    /// Nonce the mock issued for the current challenge.
    pub issued_nonce: Option<[u8; 32]>,
    /// The grant the mock accepted, if any.
    pub accepted_grant: Option<CapabilityGrant>,
    /// Highest counter the mock has seen, for replay rejection.
    pub high_counter: Option<u64>,
    /// Set when the mock tore the session down.
    pub wiped: bool,
}

impl MockKernel {
    pub fn new(root: HybridVerifyingKey) -> Self {
        Self {
            root,
            inbox: Vec::new(),
            outbox: Vec::new(),
            issued_nonce: None,
            accepted_grant: None,
            high_counter: None,
            wiped: false,
        }
    }

    /// Queue a challenge the way the driver would after receiving `Hello`.
    pub fn queue_challenge(&mut self, nonce: [u8; 32]) {
        self.issued_nonce = Some(nonce);
        self.outbox.push(Frame {
            opcode: OpCode::AttestChallenge,
            flags: 0,
            payload: nonce.to_vec(),
        });
    }

    /// Queue a grant acceptance the way the driver would after verifying one.
    pub fn queue_grant_accept(&mut self) {
        self.outbox.push(Frame {
            opcode: OpCode::CapabilityGrant,
            flags: 0,
            payload: Vec::new(),
        });
    }

    /// Queue a refusal, e.g. because the driver's replay window rejected a frame.
    pub fn queue_refuse(&mut self, code: u8) {
        self.outbox.push(Frame {
            opcode: OpCode::Refuse,
            flags: 0,
            payload: vec![code],
        });
    }

    pub fn sent(&self) -> &[Frame] {
        &self.inbox
    }

    /// Verify and record a grant, exactly as the driver does. Returns the same errors the
    /// driver would surface, so a test failure here means the driver would have refused too.
    pub fn accept_grant(
        &mut self,
        grant: &CapabilityGrant,
        now: u64,
    ) -> Result<(), HandshakeError> {
        grant.verify(&self.root, now)?;
        if let Some(nonce) = self.issued_nonce {
            if grant.token.handshake_nonce != nonce {
                return Err(HandshakeError::BadAttestation);
            }
        } else {
            return Err(HandshakeError::BadAttestation);
        }
        self.accepted_grant = Some(grant.clone());
        Ok(())
    }

    /// Enforce the replay window on a data frame counter.
    pub fn accept_counter(&mut self, counter: u64) -> Result<(), HandshakeError> {
        match self.high_counter {
            Some(h) if counter <= h => Err(HandshakeError::BadAttestation),
            _ => {
                self.high_counter = Some(counter);
                Ok(())
            }
        }
    }
}

impl KernelLink for MockKernel {
    fn send(&mut self, frame: &Frame) -> Result<(), IpcError> {
        self.inbox.push(frame.clone());
        Ok(())
    }

    fn recv(&mut self) -> Result<Frame, IpcError> {
        if self.outbox.is_empty() {
            return Err(IpcError::Io);
        }
        Ok(self.outbox.remove(0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    /// In-memory duplex channel: writes land in `buf`, reads consume it. Exercises the real
    /// `StreamLink` code path without a device node.
    struct Duplex(Vec<u8>);

    impl Write for Duplex {
        fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
            self.0.extend_from_slice(data);
            Ok(data.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl Read for Duplex {
        fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
            let n = out.len().min(self.0.len());
            out[..n].copy_from_slice(&self.0[..n]);
            self.0.drain(..n);
            Ok(n)
        }
    }

    #[test]
    fn stream_link_roundtrips_frames() {
        let mut link = StreamLink::new(Duplex(Vec::new()));
        link.send(&Frame::new(OpCode::Hello, b"hi".to_vec()).expect("frame"))
            .expect("send");

        let got = link.recv().expect("recv");
        assert_eq!(got.opcode, OpCode::Hello);
        assert_eq!(got.payload, b"hi");
    }

    #[test]
    fn stream_link_refuses_oversized_declared_frame() {
        let mut raw = Vec::new();
        raw.extend_from_slice(&sovereign_ipc::FRAME_MAGIC);
        raw.push(sovereign_ipc::PROTOCOL_VERSION);
        raw.push(OpCode::Data as u8);
        raw.extend_from_slice(&0u16.to_be_bytes());
        raw.extend_from_slice(&u32::MAX.to_be_bytes());

        let mut cursor = Cursor::new(raw);
        let mut link = StreamLink::new(&mut cursor);
        assert!(matches!(
            link.recv().unwrap_err(),
            IpcError::FrameTooLarge { .. }
        ));
    }

    #[test]
    fn stream_link_survives_truncated_frame() {
        let mut raw = Vec::new();
        raw.extend_from_slice(&sovereign_ipc::FRAME_MAGIC);
        raw.push(sovereign_ipc::PROTOCOL_VERSION);
        raw.push(OpCode::Data as u8);
        raw.extend_from_slice(&0u16.to_be_bytes());
        raw.extend_from_slice(&16u32.to_be_bytes());
        raw.extend_from_slice(&[0u8; 4]); // short payload

        let mut cursor = Cursor::new(raw);
        let mut link = StreamLink::new(&mut cursor);
        assert_eq!(link.recv().unwrap_err(), IpcError::Io);
    }
}
