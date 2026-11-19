//! User-space bridge between a plug-in device and the Sovereign kernel driver.
//!
//! This crate is the only place where the three concerns meet:
//!
//! 1. [`handshake`] decides whether a device may exist in the system at all;
//! 2. [`session`] decides what that device may do, and seals its traffic;
//! 3. [`link`] carries bytes to and from the driver without being trusted.
//!
//! The layering is the security property. The link cannot grant rights, the session cannot
//! invent them, and the handshake cannot widen them past the platform ceiling.

#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::panic)]
// Tests assert on failures, so they are allowed to unwrap and panic.
#![cfg_attr(
    test,
    allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)
)]

pub mod handshake;
pub mod link;
pub mod session;

pub use handshake::{
    attestation_payload, AttestationClaim, CapabilityGrant, DeviceCertificate, Handshake,
    HandshakeError, HandshakeState, CHALLENGE_TTL_SECS, DEFAULT_SESSION_SECS,
    PLUGIN_RIGHTS_CEILING,
};
pub use link::{KernelLink, StreamLink};
pub use session::{OpenedFrame, Session};
