//! Tamper-evident audit ledger.
//!
//! ## The problem this solves
//!
//! "Log everything" is the easy half. The hard half is that an attacker who owns the machine can
//! also edit the log. A plain append-only file is evidence of nothing: whoever can write it can
//! rewrite history and leave no trace.
//!
//! This ledger makes editing *detectable* rather than *impossible*. Each entry commits to the
//! hash of the one before it, so removing, reordering, or altering any entry breaks every hash
//! after it. Periodically the head is signed with the hybrid key. A verifier that holds the
//! public key can then prove:
//!
//! * the entries it was given are internally consistent (no gap, no reorder, no edit);
//! * the head it was given is the head the signer committed to at some point in time.
//!
//! ## What it cannot do, and this matters
//!
//! A signature over the head proves the head existed. It does **not** prove that no entry was
//! appended after the last checkpoint — an attacker with write access can append entries and
//! never sign again. The defence is out-of-band: publish checkpoints somewhere the attacker
//! cannot write (a second machine, a transparency log, paper), and treat a ledger whose head
//! runs ahead of its newest checkpoint as suspect. [`Ledger::verify`] reports that state
//! explicitly rather than hiding it.
//!
//! Likewise, a ledger with zero entries and a ledger whose entries were all deleted look the
//! same to someone who only has the file. Anchoring the checkpoint fixes that; nothing else can.

use sha2::{Digest, Sha256};

use sovereign_crypto::{CryptoError, HybridSignature, HybridSigningKey, HybridVerifyingKey};

/// Domain separation for entry hashes, so a ledger hash cannot be confused with any other
/// SHA-256 in the system.
const ENTRY_LABEL: &[u8] = b"SOVEREIGN/v1/ledger-entry";
/// Domain separation for checkpoint signatures.
const CHECKPOINT_LABEL: &[u8] = b"SOVEREIGN/v1/ledger-checkpoint";

/// Hash of the entry before the first one. All-zero is conventional and unambiguous: a real
/// entry hash is a SHA-256 output, which is never all zeros in practice.
pub const GENESIS: [u8; 32] = [0u8; 32];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LedgerError {
    /// The chain does not link: an entry's `prev` is not the previous entry's `hash`.
    BrokenChain { index: usize },
    /// The entry's own hash does not match its contents, so the entry was edited.
    EntryTampered { index: usize },
    /// Sequence numbers are not 0, 1, 2, ... — an entry was removed or duplicated.
    SequenceGap { index: usize },
    /// A checkpoint does not verify under the supplied key.
    BadCheckpoint,
    /// A checkpoint names a head hash that is not the one the chain produces.
    CheckpointMismatch,
    /// Entries exist beyond the last signed checkpoint. Not necessarily an attack, but it means
    /// the tail is not covered by any signature.
    UnsignedTail { entries: usize, checkpointed: usize },
    /// Fewer entries were supplied than the checkpoint claims exist.
    Truncated { have: usize, need: usize },
}

impl core::fmt::Display for LedgerError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::BrokenChain { index } => write!(f, "chain broken at entry {index}"),
            Self::EntryTampered { index } => write!(f, "entry {index} does not match its hash"),
            Self::SequenceGap { index } => write!(f, "sequence gap at entry {index}"),
            Self::BadCheckpoint => write!(f, "checkpoint signature invalid"),
            Self::CheckpointMismatch => write!(f, "checkpoint does not match the chain head"),
            Self::UnsignedTail {
                entries,
                checkpointed,
            } => write!(
                f,
                "{entries} entries, only {checkpointed} covered by a signed checkpoint"
            ),
            Self::Truncated { have, need } => {
                write!(f, "{have} entries present, checkpoint covers {need}")
            }
        }
    }
}

impl std::error::Error for LedgerError {}

/// One appended record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// 0, 1, 2, ... — position in the log.
    pub seq: u64,
    /// Unix seconds, supplied by the caller. The ledger does not read the clock, so it stays
    /// testable and does not depend on a kernel time source.
    pub at: u64,
    /// Dotted event kind, e.g. `gate.grant.accepted`. Free-form but length-bounded.
    pub kind: String,
    /// Event payload. Opaque to the ledger; the hash covers it byte for byte.
    pub body: Vec<u8>,
    /// Hash of the previous entry, or [`GENESIS`] for the first.
    pub prev: [u8; 32],
    /// `H(ENTRY_LABEL ‖ seq ‖ at ‖ len(kind) ‖ kind ‖ len(body) ‖ body ‖ prev)`.
    pub hash: [u8; 32],
}

/// Maximum length of a `kind` string. Bounded so a hostile writer cannot make the ledger
/// allocate without limit, and so `kind` always fits comfortably in an audit line.
pub const MAX_KIND: usize = 96;

impl Entry {
    fn hash_of(seq: u64, at: u64, kind: &[u8], body: &[u8], prev: &[u8; 32]) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(ENTRY_LABEL);
        h.update(seq.to_be_bytes());
        h.update(at.to_be_bytes());
        h.update((kind.len() as u32).to_be_bytes());
        h.update(kind);
        h.update((body.len() as u32).to_be_bytes());
        h.update(body);
        h.update(prev);
        h.finalize().into()
    }

    /// Recompute the hash from the entry's own contents, for tamper detection.
    pub fn recompute_hash(&self) -> [u8; 32] {
        Self::hash_of(
            self.seq,
            self.at,
            self.kind.as_bytes(),
            &self.body,
            &self.prev,
        )
    }

    pub fn is_intact(&self) -> bool {
        self.recompute_hash() == self.hash
    }
}

/// A signed commitment to the state of the chain at some point.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Checkpoint {
    /// Number of entries covered.
    pub entries: usize,
    /// Hash of the last covered entry.
    pub head: [u8; 32],
    /// Signature over `CHECKPOINT_LABEL ‖ entries ‖ head`.
    pub sig: HybridSignature,
}

impl Checkpoint {
    fn message(entries: usize, head: &[u8; 32]) -> Vec<u8> {
        let mut m = Vec::with_capacity(8 + 32);
        m.extend_from_slice(&(entries as u64).to_be_bytes());
        m.extend_from_slice(head);
        m
    }
}

/// Append-only log with a hash chain.
#[derive(Debug, Default, Clone)]
pub struct Ledger {
    entries: Vec<Entry>,
}

impl Ledger {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }

    /// Current head hash: the last entry's hash, or [`GENESIS`] when empty.
    pub fn head(&self) -> [u8; 32] {
        self.entries.last().map_or(GENESIS, |e| e.hash)
    }

    /// Append a record. Refuses an empty or over-long `kind` and bodies above `MAX_BODY`.
    pub fn append(&mut self, at: u64, kind: &str, body: &[u8]) -> Result<&Entry, LedgerError> {
        const MAX_BODY: usize = 1024 * 1024;
        if kind.is_empty() || kind.len() > MAX_KIND || body.len() > MAX_BODY {
            return Err(LedgerError::EntryTampered {
                index: self.entries.len(),
            });
        }

        let seq = self.entries.len() as u64;
        let prev = self.head();
        let hash = Entry::hash_of(seq, at, kind.as_bytes(), body, &prev);
        self.entries.push(Entry {
            seq,
            at,
            kind: kind.to_owned(),
            body: body.to_vec(),
            prev,
            hash,
        });
        Ok(self.entries.last().expect("just pushed"))
    }

    /// Sign the current head.
    ///
    /// Signing is expensive (SLH-DSA is not involved here — this is the two-half hybrid — but it
    /// is still not free), so call it periodically rather than per entry.
    pub fn checkpoint(&self, key: &HybridSigningKey) -> Result<Checkpoint, CryptoError> {
        let entries = self.entries.len();
        let head = self.head();
        let sig = key.sign(CHECKPOINT_LABEL, &Checkpoint::message(entries, &head))?;
        Ok(Checkpoint { entries, head, sig })
    }

    /// Verify the chain end to end against an optional checkpoint.
    ///
    /// Returns the number of entries the checkpoint covers on success. An empty ledger with no
    /// checkpoint verifies as zero entries — which is honest: there is nothing to check.
    pub fn verify(
        &self,
        vk: Option<&HybridVerifyingKey>,
        checkpoint: Option<&Checkpoint>,
    ) -> Result<usize, LedgerError> {
        let mut prev = GENESIS;
        for (i, e) in self.entries.iter().enumerate() {
            if e.seq != i as u64 {
                return Err(LedgerError::SequenceGap { index: i });
            }
            if !e.is_intact() {
                return Err(LedgerError::EntryTampered { index: i });
            }
            if e.prev != prev {
                return Err(LedgerError::BrokenChain { index: i });
            }
            prev = e.hash;
        }

        let Some(cp) = checkpoint else {
            // No anchor: the chain is internally consistent, but nothing proves it is the real
            // chain. Callers that need that must supply a checkpoint.
            return Ok(self.entries.len());
        };

        if cp.entries > self.entries.len() {
            return Err(LedgerError::Truncated {
                have: self.entries.len(),
                need: cp.entries,
            });
        }

        // The checkpoint must cover a prefix whose hash equals the signed head. If entries were
        // removed from the middle, the hash at that index will not match.
        let covered_head = if cp.entries == 0 {
            GENESIS
        } else {
            self.entries[cp.entries - 1].hash
        };
        if covered_head != cp.head {
            return Err(LedgerError::CheckpointMismatch);
        }

        if let Some(vk) = vk {
            vk.verify(
                CHECKPOINT_LABEL,
                &Checkpoint::message(cp.entries, &cp.head),
                &cp.sig,
            )
            .map_err(|_| LedgerError::BadCheckpoint)?;
        }

        if self.entries.len() > cp.entries {
            // Not an error to report as success: the tail is real but unsigned.
            return Err(LedgerError::UnsignedTail {
                entries: self.entries.len(),
                checkpointed: cp.entries,
            });
        }

        Ok(cp.entries)
    }

    /// Serialise the whole chain, one entry per line, for storage or transport.
    ///
    /// A deliberately simple line format: an auditor should be able to read it with `awk`, not
    /// need this crate. Fields are hex so no escaping rules apply.
    pub fn encode(&self) -> String {
        use core::fmt::Write as _;
        let mut out = String::new();
        for e in &self.entries {
            let _ = writeln!(
                out,
                "{}\t{}\t{}\t{}\t{}\t{}",
                e.seq,
                e.at,
                hex(&e.prev),
                hex(&e.hash),
                e.kind,
                hex(&e.body)
            );
        }
        out
    }

    /// Parse [`Ledger::encode`] output and verify it in one step.
    ///
    /// Re-verification is the point: a ledger that was edited on disk is caught here, because
    /// every hash is recomputed from the parsed contents rather than trusted.
    pub fn decode_and_verify(
        text: &str,
        vk: Option<&HybridVerifyingKey>,
        checkpoint: Option<&Checkpoint>,
    ) -> Result<Self, LedgerError> {
        let mut ledger = Ledger::new();
        for line in text.lines() {
            if line.is_empty() {
                continue;
            }
            let mut f = line.split('\t');
            let seq: u64 =
                f.next()
                    .and_then(|v| v.parse().ok())
                    .ok_or(LedgerError::EntryTampered {
                        index: ledger.len(),
                    })?;
            let at: u64 =
                f.next()
                    .and_then(|v| v.parse().ok())
                    .ok_or(LedgerError::EntryTampered {
                        index: ledger.len(),
                    })?;
            let prev = unhex32(f.next()).ok_or(LedgerError::EntryTampered {
                index: ledger.len(),
            })?;
            let hash = unhex32(f.next()).ok_or(LedgerError::EntryTampered {
                index: ledger.len(),
            })?;
            let kind = f
                .next()
                .ok_or(LedgerError::EntryTampered {
                    index: ledger.len(),
                })?
                .to_owned();
            let body = unhex(f.next().unwrap_or("")).ok_or(LedgerError::EntryTampered {
                index: ledger.len(),
            })?;
            ledger.entries.push(Entry {
                seq,
                at,
                kind,
                body,
                prev,
                hash,
            });
        }
        ledger.verify(vk, checkpoint)?;
        Ok(ledger)
    }
}

fn hex(bytes: &[u8]) -> String {
    use core::fmt::Write as _;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(s.len() / 2);
    for pair in bytes.chunks(2) {
        let hi = (pair[0] as char).to_digit(16)?;
        let lo = (pair[1] as char).to_digit(16)?;
        out.push(((hi << 4) | lo) as u8);
    }
    Some(out)
}

fn unhex32(field: Option<&str>) -> Option<[u8; 32]> {
    let v = unhex(field?)?;
    v.try_into().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use sovereign_crypto::labels;

    fn key() -> HybridSigningKey {
        HybridSigningKey::from_seeds([0x11; 48], [0x22; 32])
    }

    fn sample() -> Ledger {
        let mut l = Ledger::new();
        l.append(1000, "gate.grant.accepted", b"device-1")
            .expect("append");
        l.append(1001, "gate.token.revoked", b"device-2")
            .expect("append");
        l.append(1002, "tunnel.peer.joined", b"peer-9")
            .expect("append");
        l
    }

    #[test]
    fn chain_links_and_verifies() {
        let l = sample();
        assert_eq!(l.len(), 3);
        assert_eq!(l.entries()[0].prev, GENESIS);
        assert_eq!(l.entries()[1].prev, l.entries()[0].hash);
        assert_eq!(l.verify(None, None), Ok(3));
    }

    #[test]
    fn editing_an_entry_is_caught() {
        let mut l = sample();
        l.entries[1].body = b"device-EVIL".to_vec();
        assert_eq!(
            l.verify(None, None),
            Err(LedgerError::EntryTampered { index: 1 })
        );
    }

    #[test]
    fn editing_an_entry_and_fixing_its_hash_still_breaks_the_next_link() {
        let mut l = sample();
        l.entries[1].body = b"device-EVIL".to_vec();
        l.entries[1].hash = l.entries[1].recompute_hash();
        assert_eq!(
            l.verify(None, None),
            Err(LedgerError::BrokenChain { index: 2 })
        );
    }

    #[test]
    fn removing_an_entry_is_caught() {
        let mut l = sample();
        l.entries.remove(1);
        // Entry 2 now has seq 2 in slot 1: a sequence gap is reported before the broken link,
        // which is the more precise diagnosis.
        assert!(matches!(
            l.verify(None, None),
            Err(LedgerError::SequenceGap { index: 1 })
        ));
    }

    #[test]
    fn reordering_is_caught() {
        let mut l = sample();
        l.entries.swap(0, 1);
        assert!(l.verify(None, None).is_err());
    }

    #[test]
    fn appending_a_forged_entry_without_rehashing_is_caught() {
        let mut l = sample();
        let mut e = l.entries[2].clone();
        e.seq = 3;
        e.body = b"forged".to_vec();
        l.entries.push(e);
        assert_eq!(
            l.verify(None, None),
            Err(LedgerError::EntryTampered { index: 3 })
        );
    }

    #[test]
    fn a_signed_checkpoint_verifies() {
        let l = sample();
        let k = key();
        let cp = l.checkpoint(&k).expect("checkpoint");
        assert_eq!(l.verify(Some(&k.verifying_key()), Some(&cp)), Ok(3));
    }

    #[test]
    fn a_checkpoint_from_another_key_is_refused() {
        let l = sample();
        let cp = l.checkpoint(&key()).expect("checkpoint");
        let other = HybridSigningKey::from_seeds([0x33; 48], [0x44; 32]);
        assert_eq!(
            l.verify(Some(&other.verifying_key()), Some(&cp)),
            Err(LedgerError::BadCheckpoint)
        );
    }

    #[test]
    fn a_checkpoint_over_a_different_head_is_refused() {
        let mut l = sample();
        let k = key();
        let cp = l.checkpoint(&k).expect("checkpoint");
        l.append(1003, "gate.grant.accepted", b"device-4")
            .expect("append");
        // Re-hash the new entry so the chain is internally valid, then claim the old checkpoint.
        let prev = l.entries[2].hash;
        l.entries[3].prev = prev;
        l.entries[3].hash = l.entries[3].recompute_hash();
        assert_eq!(
            l.verify(Some(&k.verifying_key()), Some(&cp)),
            Err(LedgerError::UnsignedTail {
                entries: 4,
                checkpointed: 3
            })
        );
    }

    #[test]
    fn truncation_below_a_checkpoint_is_refused() {
        let mut l = sample();
        let k = key();
        let cp = l.checkpoint(&k).expect("checkpoint");
        l.entries.truncate(1);
        assert_eq!(
            l.verify(Some(&k.verifying_key()), Some(&cp)),
            Err(LedgerError::Truncated { have: 1, need: 3 })
        );
    }

    #[test]
    fn deleting_the_tail_after_a_checkpoint_is_not_silently_accepted() {
        // A truncated ledger whose checkpoint still matches the prefix is the dangerous case:
        // it looks consistent. It is reported as Truncated because the checkpoint claims more
        // entries than exist.
        let mut l = sample();
        let k = key();
        let cp = l.checkpoint(&k).expect("checkpoint");
        l.entries.truncate(2);
        assert!(matches!(
            l.verify(Some(&k.verifying_key()), Some(&cp)),
            Err(LedgerError::Truncated { .. })
        ));
    }

    #[test]
    fn encode_and_decode_roundtrip_preserves_verification() {
        let l = sample();
        let k = key();
        let cp = l.checkpoint(&k).expect("checkpoint");
        let text = l.encode();
        let restored =
            Ledger::decode_and_verify(&text, Some(&k.verifying_key()), Some(&cp)).expect("verify");
        assert_eq!(restored.entries(), l.entries());
    }

    #[test]
    fn a_ledger_edited_on_disk_fails_to_load() {
        let l = sample();
        // Bodies are hex on the wire, so an editor flipping a readable byte of the plaintext
        // shows up here as a flipped hex digit. Edit the hex field, not the plaintext.
        let text = l.encode();
        let tampered = text.replacen("6465766963652d31", "6465766963652d39", 1);
        assert_ne!(text, tampered, "the fixture must actually change");
        assert!(Ledger::decode_and_verify(&tampered, None, None).is_err());
    }

    #[test]
    fn an_empty_ledger_verifies_as_empty() {
        let l = Ledger::new();
        assert_eq!(l.verify(None, None), Ok(0));
        assert_eq!(l.head(), GENESIS);
    }

    #[test]
    fn oversized_or_empty_kind_is_refused() {
        let mut l = Ledger::new();
        assert!(l.append(0, "", b"x").is_err());
        assert!(l.append(0, &"k".repeat(MAX_KIND + 1), b"x").is_err());
        assert!(l.append(0, "ok", b"x").is_ok());
    }

    #[test]
    fn entry_hashes_are_domain_separated_from_other_sha256_use() {
        // A bare SHA-256 of the body must not equal the entry hash, or a body could be swapped
        // for a preimage from elsewhere in the system.
        let mut l = Ledger::new();
        let e = l.append(0, "k", b"body").expect("append").clone();
        let mut h = Sha256::new();
        h.update(b"body");
        let bare: [u8; 32] = h.finalize().into();
        assert_ne!(e.hash, bare);
    }

    #[test]
    fn labels_are_the_ones_the_rest_of_the_system_uses() {
        // Guard against a copy-paste label that silently changes every historical hash.
        assert_eq!(ENTRY_LABEL, b"SOVEREIGN/v1/ledger-entry");
        assert_eq!(CHECKPOINT_LABEL, b"SOVEREIGN/v1/ledger-checkpoint");
        assert_ne!(labels::CAPABILITY, CHECKPOINT_LABEL);
    }
}
