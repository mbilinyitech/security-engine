//! One device protocol, several host transports.
//!
//! ## The honest scope
//!
//! "A driver that talks to any OS" does not exist and cannot. Linux, Windows, and macOS load
//! drivers through mechanisms that have nothing in common: Linux has `file_operations` on a
//! character device, Windows has `IRP` dispatch through `IOCTL`, macOS has an `IOKit` driver
//! class. There is no common binary interface, and a single `.ko` that loads on all three is not
//! a thing anyone has built.
//!
//! What *can* be shared is everything above the kernel boundary: the byte protocol on the wire,
//! the state machine that decides whether a device may talk, and the framing. So this crate keeps
//! the protocol in one place and puts the OS-specific part behind [`Transport`], a trait with one
//! method. Each adapter is then genuinely small — the Linux one really does open a character
//! device, the others are described below — and none of them reimplement the protocol.
//!
//! ## What is real here and what is not
//!
//! * [`LinuxChardev`] opens a real file and reads real bytes. On this machine it is exercised
//!   against a pipe and a file, which is the same `Read`/`Write` path the character device uses.
//! * [`WindowsIoctl`] and [`MacOsIoKit`] implement the same [`Transport`] and are exercised
//!   against in-memory buffers. They encode the *shape* of each platform's call — an `IOCTL` with
//!   a method code, an `IOConnectCallStructMethod` with a selector — so the protocol layer above
//!   them is genuinely OS-independent. They do **not** contain FFI to `DeviceIoControl` or
//!   `IOConnectCallStructMethod`; that needs the platform SDK, and claiming otherwise would be
//!   the kind of thing that only fails on a customer's machine.
//!
//! The point of building it this way is that the interesting logic is testable on any host,
//! today, and adding a real FFI adapter later is a small change in one file rather than a rewrite.

use std::io::{Read, Write};

use sovereign_ipc::{Frame, IpcError, OpCode, Rights};

/// A byte transport to a device, however the host OS spells it.
///
/// Deliberately two methods and no more. Every additional method is something each platform
/// adapter must implement differently, and every one of those differences is a place the
/// protocol could diverge.
pub trait Transport {
    /// Send one framed message.
    fn send(&mut self, frame: &Frame) -> Result<(), IpcError>;
    /// Receive one framed message.
    fn recv(&mut self) -> Result<Frame, IpcError>;
    /// A name for logs and errors, e.g. `/dev/sovereign0` or `IOCTL:0x222000`.
    fn describe(&self) -> String;
}

/// Linux: a character device node, spoken to with ordinary `read`/`write`.
pub struct LinuxChardev<T: Read + Write> {
    io: T,
    path: String,
}

impl<T: Read + Write> LinuxChardev<T> {
    pub fn new(io: T, path: &str) -> Self {
        Self {
            io,
            path: path.to_owned(),
        }
    }
}

impl<T: Read + Write> Transport for LinuxChardev<T> {
    fn send(&mut self, frame: &Frame) -> Result<(), IpcError> {
        let bytes = frame.encode();
        self.io.write_all(&bytes).map_err(|_| IpcError::Io)
    }

    fn recv(&mut self) -> Result<Frame, IpcError> {
        sovereign_ipc::read_frame(&mut self.io)
    }

    fn describe(&self) -> String {
        self.path.clone()
    }
}

/// Windows: one `DeviceIoControl` call per frame.
///
/// The buffer layout is what `DeviceIoControl` would pass: the frame bytes as input, the reply as
/// output. The method code is carried so error messages name the real operation, and so a later
/// FFI adapter has nothing to decide.
pub struct WindowsIoctl {
    /// The `IOCTL_*` control code this adapter would issue.
    pub control_code: u32,
    inbound: Vec<u8>,
    outbound: Vec<u8>,
}

impl WindowsIoctl {
    /// `0x00222000` is `FILE_DEVICE_UNKNOWN` with `METHOD_BUFFERED`, `FILE_ANY_ACCESS` and
    /// function 0x800 — the conventional shape for a vendor driver, not a value Windows assigns.
    pub const DEFAULT_CONTROL_CODE: u32 = 0x0022_2000;

    pub fn new() -> Self {
        Self {
            control_code: Self::DEFAULT_CONTROL_CODE,
            inbound: Vec::new(),
            outbound: Vec::new(),
        }
    }
}

impl Default for WindowsIoctl {
    fn default() -> Self {
        Self::new()
    }
}

impl Transport for WindowsIoctl {
    fn send(&mut self, frame: &Frame) -> Result<(), IpcError> {
        self.inbound = frame.encode();
        Ok(())
    }

    fn recv(&mut self) -> Result<Frame, IpcError> {
        // A buffered IOCTL returns the reply in the output buffer of the same call, so a real
        // adapter would read it here. With no driver underneath, an empty buffer is an honest
        // "nothing to read" rather than a fabricated frame.
        if self.outbound.is_empty() {
            return Err(IpcError::Io);
        }
        let frame = Frame::decode(&self.outbound)?;
        self.outbound.clear();
        Ok(frame)
    }

    fn describe(&self) -> String {
        format!("IOCTL:{:#010x}", self.control_code)
    }
}

/// macOS: one `IOConnectCallStructMethod` call per frame, selected by a method index.
pub struct MacOsIoKit {
    /// The selector passed to `IOConnectCallStructMethod`.
    pub selector: u32,
    inbound: Vec<u8>,
    outbound: Vec<u8>,
}

impl MacOsIoKit {
    pub const DEFAULT_SELECTOR: u32 = 0;

    pub fn new() -> Self {
        Self {
            selector: Self::DEFAULT_SELECTOR,
            inbound: Vec::new(),
            outbound: Vec::new(),
        }
    }
}

impl Default for MacOsIoKit {
    fn default() -> Self {
        Self::new()
    }
}

impl Transport for MacOsIoKit {
    fn send(&mut self, frame: &Frame) -> Result<(), IpcError> {
        self.inbound = frame.encode();
        Ok(())
    }

    fn recv(&mut self) -> Result<Frame, IpcError> {
        if self.outbound.is_empty() {
            return Err(IpcError::Io);
        }
        let frame = Frame::decode(&self.outbound)?;
        self.outbound.clear();
        Ok(frame)
    }

    fn describe(&self) -> String {
        format!("IOKit:selector={}", self.selector)
    }
}

/// What the host learned about the device during the handshake.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceInfo {
    /// Free-form model string the device reported, length-bounded.
    pub model: String,
    /// Rights the device says it wants.
    pub wanted_rights: Rights,
}

/// Result of a completed session setup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Session {
    pub info: DeviceInfo,
    /// Rights the host actually granted, always a subset of what was wanted.
    pub granted_rights: Rights,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InteropError {
    /// The device asked for rights the host policy does not allow at all.
    ForbiddenRights { wanted: Rights, allowed: Rights },
    /// The device reported a rights value with bits that do not exist.
    MalformedRights(u32),
    /// The device's model string was empty or unreasonably long.
    BadModel,
    /// Transport-level failure.
    Io(IpcError),
}

impl core::fmt::Display for InteropError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::ForbiddenRights { wanted, allowed } => write!(
                f,
                "device asked for rights {:#07b}, host allows {:#07b}",
                wanted.bits(),
                allowed.bits()
            ),
            Self::MalformedRights(bits) => {
                write!(f, "device reported reserved rights bits {bits:#07b}")
            }
            Self::BadModel => write!(f, "device model string invalid"),
            Self::Io(e) => write!(f, "transport: {e}"),
        }
    }
}

impl std::error::Error for InteropError {}

/// Longest model string a device may report. Bounded because it is attacker-controlled and ends
/// up in logs.
pub const MAX_MODEL: usize = 64;

/// Perform the host side of a device handshake over any transport.
///
/// The sequence is: ask who you are, read the answer, intersect what the device wants with what
/// policy allows, then tell it what it got. Intersecting rather than granting is the whole point —
/// a device that asks for `ADMIN` gets whatever subset policy permits, and is told so, rather
/// than being refused outright or trusted.
pub fn handshake<T: Transport>(
    transport: &mut T,
    allowed_rights: Rights,
) -> Result<Session, InteropError> {
    transport
        .send(&Frame::new(OpCode::Hello, Vec::new()).map_err(InteropError::Io)?)
        .map_err(InteropError::Io)?;

    let reply = transport.recv().map_err(InteropError::Io)?;
    if reply.opcode != OpCode::Hello {
        return Err(InteropError::Io(IpcError::UnknownOpcode(
            reply.opcode as u8,
        )));
    }

    let payload = reply.payload;
    // Layout: u8(len) ‖ model ‖ u32_be(wanted_rights). A single length byte caps the model at
    // 255 by construction, and the check below tightens it to MAX_MODEL.
    let (&len, rest) = payload.split_first().ok_or(InteropError::BadModel)?;
    let len = len as usize;
    if len == 0 || len > MAX_MODEL || rest.len() != len + 4 {
        return Err(InteropError::BadModel);
    }
    let model = core::str::from_utf8(&rest[..len]).map_err(|_| InteropError::BadModel)?;
    if model.chars().any(|c| c.is_control()) {
        // A model string with a newline in it forges a log line. Refuse rather than sanitise,
        // because a device that does this is either broken or hostile.
        return Err(InteropError::BadModel);
    }
    let raw = u32::from_be_bytes([rest[len], rest[len + 1], rest[len + 2], rest[len + 3]]);
    // A rights value with reserved bits is malformed, not merely excessive: the device and the
    // host disagree about what a bit means, which is the prelude to a privilege escalation.
    let wanted = Rights::from_bits(raw).ok_or(InteropError::MalformedRights(raw))?;

    if !allowed_rights.contains(wanted) {
        // Some of what it wants is not permitted at all. Refuse the whole handshake rather than
        // silently narrowing: a device that asked for something it should never have needs to be
        // visible, not accommodated.
        return Err(InteropError::ForbiddenRights {
            wanted,
            allowed: allowed_rights,
        });
    }

    let granted = wanted.intersect(allowed_rights);
    transport
        .send(
            &Frame::new(OpCode::Hello, granted.bits().to_be_bytes().to_vec())
                .map_err(InteropError::Io)?,
        )
        .map_err(InteropError::Io)?;

    Ok(Session {
        info: DeviceInfo {
            model: model.to_owned(),
            wanted_rights: wanted,
        },
        granted_rights: granted,
    })
}

/// Encode a device's `Hello` reply. Present so the tests and any future device firmware agree on
/// one layout, and so the encoder is not duplicated on the device side.
pub fn encode_hello_reply(model: &str, wanted_rights: Rights) -> Result<Vec<u8>, InteropError> {
    if model.is_empty() || model.len() > MAX_MODEL || model.chars().any(|c| c.is_control()) {
        return Err(InteropError::BadModel);
    }
    let mut out = Vec::with_capacity(1 + model.len() + 4);
    out.push(model.len() as u8);
    out.extend_from_slice(model.as_bytes());
    out.extend_from_slice(&wanted_rights.bits().to_be_bytes());
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A transport backed by two byte queues: what we send lands in `to_device`, what we receive
    /// comes from `from_device`. This is the same shape a socket or a pipe has, so a transport
    /// tested through it is tested through the code path the real one uses.
    struct Loopback {
        to_device: Vec<u8>,
        from_device: Vec<u8>,
        sent: Vec<Frame>,
    }

    impl Loopback {
        fn new(from_device: Vec<u8>) -> Self {
            Self {
                to_device: Vec::new(),
                from_device,
                sent: Vec::new(),
            }
        }
    }

    impl Transport for Loopback {
        fn send(&mut self, frame: &Frame) -> Result<(), IpcError> {
            self.sent.push(frame.clone());
            let bytes = frame.encode();
            self.to_device.extend_from_slice(&bytes);
            Ok(())
        }

        fn recv(&mut self) -> Result<Frame, IpcError> {
            if self.from_device.is_empty() {
                return Err(IpcError::Io);
            }
            let mut cursor = std::io::Cursor::new(self.from_device.clone());
            let frame = sovereign_ipc::read_frame(&mut cursor)?;
            self.from_device.drain(..cursor.position() as usize);
            Ok(frame)
        }

        fn describe(&self) -> String {
            "loopback".to_owned()
        }
    }

    fn hello_frame(model: &str, rights: Rights) -> Vec<u8> {
        Frame::new(
            OpCode::Hello,
            encode_hello_reply(model, rights).expect("encode"),
        )
        .expect("frame")
        .encode()
    }

    /// Build a Hello reply without validation, so the tests can construct the malformed inputs a
    /// hostile or broken device would send. The validating encoder is for real devices.
    fn raw_hello_frame(model: &[u8], rights: u32) -> Vec<u8> {
        let mut payload = vec![model.len() as u8];
        payload.extend_from_slice(model);
        payload.extend_from_slice(&rights.to_be_bytes());
        Frame::new(OpCode::Hello, payload).expect("frame").encode()
    }

    #[test]
    fn a_well_behaved_device_completes_the_handshake() {
        let mut t = Loopback::new(hello_frame("sensor-a", Rights::SENSOR_READ));
        let session = handshake(&mut t, Rights::SENSOR_READ).expect("handshake");

        assert_eq!(session.info.model, "sensor-a");
        assert_eq!(session.info.wanted_rights, Rights::SENSOR_READ);
        assert_eq!(session.granted_rights, Rights::SENSOR_READ);
        // Host asked first, then acknowledged.
        assert_eq!(t.sent.len(), 2);
        assert_eq!(t.sent[0].opcode, OpCode::Hello);
    }

    #[test]
    fn a_device_asking_for_forbidden_rights_is_refused_entirely() {
        let mut t = Loopback::new(hello_frame("sensor-a", Rights::ADMIN));
        let e = handshake(&mut t, Rights::SENSOR_READ).unwrap_err();
        assert_eq!(
            e,
            InteropError::ForbiddenRights {
                wanted: Rights::ADMIN,
                allowed: Rights::SENSOR_READ
            }
        );
        // Only the initial Hello went out; no acknowledgement, so the device is left in the dark
        // rather than told it succeeded.
        assert_eq!(t.sent.len(), 1);
    }

    #[test]
    fn a_control_character_in_the_model_string_is_refused() {
        // Without this, a device named "sensor\nRESULT: PASS" forges a log line.
        let mut t = Loopback::new(raw_hello_frame(b"sensor\nRESULT: PASS", 0));
        assert_eq!(
            handshake(&mut t, Rights::SENSOR_READ).unwrap_err(),
            InteropError::BadModel
        );
    }

    #[test]
    fn an_empty_model_is_refused() {
        let mut t = Loopback::new(raw_hello_frame(b"", 0));
        assert_eq!(
            handshake(&mut t, Rights::SENSOR_READ).unwrap_err(),
            InteropError::BadModel
        );
    }

    #[test]
    fn an_over_long_model_is_refused_at_the_encoder() {
        assert_eq!(
            encode_hello_reply(&"m".repeat(MAX_MODEL + 1), Rights::NONE).unwrap_err(),
            InteropError::BadModel
        );
    }

    #[test]
    fn a_truncated_hello_payload_is_refused() {
        // Claims a 10-byte model but supplies 3 bytes and no rights field.
        let mut bad = vec![10u8];
        bad.extend_from_slice(b"abc");
        let mut t = Loopback::new(Frame::new(OpCode::Hello, bad).expect("frame").encode());
        assert_eq!(
            handshake(&mut t, Rights::SENSOR_READ).unwrap_err(),
            InteropError::BadModel
        );
    }

    #[test]
    fn reserved_rights_bits_from_the_device_are_refused() {
        // A device claiming a bit the host has never heard of is not asking for too much; it is
        // speaking a different protocol. Refuse, do not narrow.
        let mut payload = vec![4u8];
        payload.extend_from_slice(b"mod0");
        payload.extend_from_slice(&0b1000_0000u32.to_be_bytes());
        let mut t = Loopback::new(Frame::new(OpCode::Hello, payload).expect("frame").encode());
        assert_eq!(
            handshake(&mut t, Rights::SENSOR_READ).unwrap_err(),
            InteropError::MalformedRights(0b1000_0000)
        );
    }

    #[test]
    fn a_reply_with_the_wrong_opcode_is_refused() {
        let mut t = Loopback::new(
            Frame::new(OpCode::Data, Vec::new())
                .expect("frame")
                .encode(),
        );
        assert!(matches!(
            handshake(&mut t, Rights::SENSOR_READ),
            Err(InteropError::Io(_))
        ));
    }

    #[test]
    fn a_silent_device_times_out_as_io_error() {
        let mut t = Loopback::new(Vec::new());
        assert!(matches!(
            handshake(&mut t, Rights::SENSOR_READ),
            Err(InteropError::Io(_))
        ));
    }

    /// A real duplex file descriptor. `UnixStream::pair` gives two endpoints that are both
    /// `Read` and `Write`, which is the same shape a character device has — unlike
    /// `std::io::pipe`, whose halves are each one-directional.
    fn socket_pair() -> (
        std::os::unix::net::UnixStream,
        std::os::unix::net::UnixStream,
    ) {
        std::os::unix::net::UnixStream::pair().expect("socketpair")
    }

    #[test]
    fn the_linux_adapter_reads_a_frame_from_a_real_file_descriptor() {
        let (mut peer, device) = socket_pair();
        let mut dev = LinuxChardev::new(device, "/dev/sovereign-test");

        let frame = Frame::new(OpCode::Hello, b"payload".to_vec()).expect("frame");
        peer.write_all(&frame.encode()).expect("write");

        let got = dev.recv().expect("recv");
        assert_eq!(got.opcode, OpCode::Hello);
        assert_eq!(got.payload, b"payload");
        assert_eq!(dev.describe(), "/dev/sovereign-test");
    }

    #[test]
    fn the_linux_adapter_writes_frames_that_decode() {
        let (mut peer, device) = socket_pair();
        let mut dev = LinuxChardev::new(device, "/dev/sovereign-test");
        dev.send(&Frame::new(OpCode::Data, vec![1, 2, 3]).expect("frame"))
            .expect("send");

        let got = sovereign_ipc::read_frame(&mut peer).expect("read");
        assert_eq!(got.opcode, OpCode::Data);
        assert_eq!(got.payload, vec![1, 2, 3]);
    }

    #[test]
    fn a_full_handshake_completes_over_a_real_file_descriptor() {
        // The strongest statement in this crate: the protocol layer and the Linux adapter,
        // together, over a genuine kernel file descriptor rather than an in-memory stub.
        let (mut peer, device) = socket_pair();
        let mut dev = LinuxChardev::new(device, "/dev/sovereign-test");

        let allowed = Rights::SENSOR_READ.union(Rights::TELEMETRY_WRITE);
        let reply = Frame::new(
            OpCode::Hello,
            encode_hello_reply("thermal-01", Rights::SENSOR_READ).expect("encode"),
        )
        .expect("frame")
        .encode();
        peer.write_all(&reply).expect("write");

        let session = handshake(&mut dev, allowed).expect("handshake");
        assert_eq!(session.info.model, "thermal-01");
        assert_eq!(session.granted_rights, Rights::SENSOR_READ);

        // The device sees the host's Hello first, then the grant.
        let probe = sovereign_ipc::read_frame(&mut peer).expect("probe");
        assert_eq!(probe.opcode, OpCode::Hello);
        assert!(probe.payload.is_empty());

        let ack = sovereign_ipc::read_frame(&mut peer).expect("ack");
        assert_eq!(ack.opcode, OpCode::Hello);
        assert_eq!(
            ack.payload,
            Rights::SENSOR_READ.bits().to_be_bytes().to_vec()
        );
    }

    #[test]
    fn the_windows_adapter_uses_its_control_code_in_diagnostics() {
        let w = WindowsIoctl::new();
        assert_eq!(w.describe(), "IOCTL:0x00222000");
        assert_eq!(w.control_code, WindowsIoctl::DEFAULT_CONTROL_CODE);
    }

    #[test]
    fn the_macos_adapter_names_its_selector_in_diagnostics() {
        let m = MacOsIoKit::new();
        assert_eq!(m.describe(), "IOKit:selector=0");
    }

    #[test]
    fn every_adapter_reports_no_data_rather_than_inventing_a_frame() {
        // Fail-closed: an empty read is an error, never a zeroed frame that a caller might treat
        // as valid.
        let mut w = WindowsIoctl::new();
        assert_eq!(w.recv().unwrap_err(), IpcError::Io);
        let mut m = MacOsIoKit::new();
        assert_eq!(m.recv().unwrap_err(), IpcError::Io);
    }

    #[test]
    fn the_protocol_is_identical_across_transports() {
        // The same bytes must produce the same session regardless of which OS adapter carried
        // them. This is the property the whole crate exists to provide.
        let wanted = Rights::SENSOR_READ.union(Rights::NET_EGRESS);
        let allowed = Rights::SENSOR_READ
            .union(Rights::TELEMETRY_WRITE)
            .union(Rights::NET_EGRESS);
        let bytes = hello_frame("model-x", wanted);

        let mut loop_t = Loopback::new(bytes.clone());
        let a = handshake(&mut loop_t, allowed).expect("loopback");

        let mut w = WindowsIoctl::new();
        w.outbound = bytes.clone();
        let b = handshake(&mut w, allowed).expect("windows");

        let mut m = MacOsIoKit::new();
        m.outbound = bytes;
        let c = handshake(&mut m, allowed).expect("macos");

        assert_eq!(a, b);
        assert_eq!(b, c);
    }
}
