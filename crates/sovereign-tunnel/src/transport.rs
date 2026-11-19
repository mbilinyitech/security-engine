//! Real UDP transport.
//!
//! Thin, deliberately: it owns a socket and the per-peer replay filter, and nothing else. All
//! policy lives in [`crate`] so it can be tested without a network.

use std::collections::HashMap;
use std::io;
use std::net::{SocketAddr, UdpSocket};

use sovereign_ipc::SealedFrame;

use crate::{chaff_datagram, ChaffSchedule, Datagram, PeerReplay, TunnelError, MAX_DATAGRAM};

/// A UDP endpoint carrying sealed frames to and from one or more peers.
pub struct UdpTransport {
    socket: UdpSocket,
    /// One replay window per peer. Bounded by the peer count, not by traffic volume, so a
    /// stranger cannot grow this map by sending to us.
    peers: HashMap<SocketAddr, PeerReplay>,
    /// Peers we are willing to talk to. Anything else is dropped before parsing, so an
    /// unauthenticated sender cannot even reach the replay window.
    allowed: Vec<SocketAddr>,
}

impl UdpTransport {
    /// Bind to a local address. `allowed` lists the peers this endpoint will accept from; an
    /// empty list means "learn peers on first contact", which is only safe for tests.
    pub fn bind(local: &str, allowed: Vec<SocketAddr>) -> io::Result<Self> {
        let socket = UdpSocket::bind(local)?;
        Ok(Self {
            socket,
            peers: HashMap::new(),
            allowed,
        })
    }

    /// Wrap an already-bound socket. Lets a caller set socket options first, and lets tests
    /// configure an allow-list without rebinding (which races with the old socket's release).
    pub fn from_socket(socket: UdpSocket, allowed: Vec<SocketAddr>) -> Self {
        Self {
            socket,
            peers: HashMap::new(),
            allowed,
        }
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    /// Send a sealed frame to `to`, padded to a bucket.
    pub fn send_frame(&self, to: SocketAddr, frame: &SealedFrame) -> Result<usize, TunnelError> {
        let bytes = Datagram::seal(frame)?.encode()?;
        self.socket.send_to(&bytes, to).map_err(|_| TunnelError::Io)
    }

    /// Send raw cover traffic. It is not a valid frame and will be discarded by any receiver.
    pub fn send_chaff(
        &self,
        to: SocketAddr,
        schedule: &ChaffSchedule,
    ) -> Result<usize, TunnelError> {
        let bytes = chaff_datagram(schedule.bucket())?;
        self.socket.send_to(&bytes, to).map_err(|_| TunnelError::Io)
    }

    /// Receive one datagram and parse it.
    ///
    /// Returns the sender alongside the frame so the caller can answer without trusting the
    /// frame's contents to identify the peer. Chaff and malformed datagrams are reported as
    /// errors rather than silently skipped: a caller that wants to ignore them can, but it
    /// should see the volume.
    pub fn recv_frame(&mut self) -> Result<(SocketAddr, Datagram), TunnelError> {
        let mut buf = [0u8; MAX_DATAGRAM + 1];
        let (n, from) = self
            .socket
            .recv_from(&mut buf)
            .map_err(|_| TunnelError::Io)?;

        if !self.allowed.is_empty() && !self.allowed.contains(&from) {
            return Err(TunnelError::BadMagic);
        }

        // Truncation check: a datagram larger than the buffer is not one of ours, because we
        // never emit one. Refusing avoids parsing a partial frame.
        if n > MAX_DATAGRAM {
            return Err(TunnelError::TooLarge);
        }

        let datagram = Datagram::decode(buf.get(..n).ok_or(TunnelError::TooShort)?)?;

        // Transport-level replay is checked before the caller spends AEAD work on it. Note the
        // counter is *recorded* here, which means a frame that later fails to authenticate has
        // already consumed its counter. That is the safe direction: refusing a valid frame
        // costs availability, accepting a replayed one costs integrity.
        self.peers
            .entry(from)
            .or_default()
            .accept(datagram.counter())?;

        Ok((from, datagram))
    }

    /// Number of peers with a replay window.
    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }

    pub fn set_read_timeout(&self, dur: Option<std::time::Duration>) -> io::Result<()> {
        self.socket.set_read_timeout(dur)
    }
}
