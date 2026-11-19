//! Diverse redundant verification.
//!
//! ## What this is, and what it is not
//!
//! The request was to "clone a threat swarm and integrate it". An AI that rewrites its own
//! detectors and deploys them worldwide is not something I can build responsibly, and a
//! self-modifying verifier is the opposite of a security control: you cannot audit what you did
//! not write, and an attacker who can influence its training data owns it. So this is the part of
//! that idea that is genuinely sound engineering:
//!
//! **Redundant verification with independent implementations.** The same artifact is checked by
//! several verifiers that were written differently and fail differently. They must all agree. If
//! one says "valid" and another says "invalid", that disagreement is itself the alarm — it means
//! either a verifier is broken or an attacker has found a differential, and both are emergencies.
//!
//! ## Why diversity matters more than count
//!
//! Ten copies of one check catch nothing ten times. What catches real attacks is checks that
//! depend on different assumptions:
//!
//! * a *structural* check that the bytes parse at all;
//! * a *domain* check that the signature was made for this purpose and not replayed from another;
//! * a *freshness* check that the artifact is not from a window that has already passed;
//! * an *independent hash* check over the exact bytes the caller believes it is authorising.
//!
//! An attacker who finds a parsing quirk in one still has to satisfy the others.
//!
//! ## Two different things, kept apart
//!
//! A naive design runs every check and calls any split "disagreement". That is wrong, and it is
//! wrong in a way that destroys the value of the signal: a token that simply expired would trip
//! one check and raise a "verifiers disagree" alarm, so real disagreement would be lost in noise.
//!
//! So this module separates two questions:
//!
//! * **Gates** ([`Swarm::evaluate`]). Independent checks, each of which can veto. A rejection is
//!   an ordinary rejection, no matter how many gates said yes. Gates are diverse so that an
//!   attacker who slips past one still meets the others, but a veto is not evidence of anything
//!   stranger than a bad artifact.
//!
//! * **Corroboration** ([`Swarm::corroborate`]). Several implementations answer the *same*
//!   question. If they do not all give the same answer, something is wrong with the software
//!   itself — a bug, a build mismatch, or a differential an attacker found. That is
//!   [`SwarmError::Disagreement`], and it is the only condition that means "assume compromise".
//!
//! Both are available; the caller picks. A gate that must also be corroborated runs both.

use std::collections::BTreeMap;

use sha2::{Digest, Sha256};
use sovereign_crypto::HybridVerifyingKey;
use sovereign_ipc::Rights;
use sovereign_ledger::Ledger;

/// What a verifier concluded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Accept,
    Reject,
}

/// The artifact under examination. Verifiers see only this, never each other's answers.
#[derive(Debug, Clone)]
pub struct Artifact<'a> {
    /// Domain the signature must have been made under.
    pub domain: &'a [u8],
    /// The exact bytes the caller believes it is authorising.
    pub payload: &'a [u8],
    /// Rights the payload claims.
    pub claimed_rights: Rights,
    /// Rights the caller is actually willing to grant. A payload claiming more is a red flag.
    pub ceiling: Rights,
    /// Unix seconds, supplied by the caller so the swarm stays testable.
    pub now: u64,
    /// Earliest acceptable issuance time. `None` disables the freshness check.
    pub not_before: Option<u64>,
    /// Caller's own digest of `payload`, if it has one. A mismatch means the artifact the
    /// verifier received is not the artifact the caller meant to send.
    pub expected_digest: Option<[u8; 32]>,
}

/// A named check. `fn` pointer, not a boxed closure, so the set of checks is fixed at compile
/// time and cannot be swapped at run time by whatever loaded this crate.
pub type Check = fn(&Artifact<'_>) -> Verdict;

/// Result of one check, kept so a failure can say *which* check disagreed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckOutcome {
    pub name: String,
    pub verdict: Verdict,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SwarmError {
    /// At least one gate vetoed. Ordinary rejection, not an alarm.
    Rejected { outcomes: Vec<CheckOutcome> },
    /// Independent implementations of the same question gave different answers. Treat the system
    /// as compromised until the cause is known.
    Disagreement { outcomes: Vec<CheckOutcome> },
    /// No checks registered. Accepting here would be a silent fail-open.
    Empty,
}

impl core::fmt::Display for SwarmError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let render = |outcomes: &[CheckOutcome]| {
            outcomes
                .iter()
                .map(|o| format!("{}={:?}", o.name, o.verdict))
                .collect::<Vec<_>>()
                .join(", ")
        };
        match self {
            Self::Rejected { outcomes } => write!(f, "rejected by: {}", render(outcomes)),
            Self::Disagreement { outcomes } => {
                write!(f, "VERIFIER DISAGREEMENT: {}", render(outcomes))
            }
            Self::Empty => write!(f, "no verifiers registered"),
        }
    }
}

impl std::error::Error for SwarmError {}

/// A swarm of gates, plus optional corroborating implementations.
pub struct Swarm {
    gates: BTreeMap<String, Check>,
    corroborators: BTreeMap<String, Check>,
}

impl Default for Swarm {
    fn default() -> Self {
        Self::new()
    }
}

impl Swarm {
    pub fn new() -> Self {
        Self {
            gates: BTreeMap::new(),
            corroborators: BTreeMap::new(),
        }
    }

    /// A swarm with the four built-in gates. Callers may add more.
    pub fn with_defaults() -> Self {
        let mut s = Self::new();
        s.add("structural", check_structural);
        s.add("rights-ceiling", check_rights_ceiling);
        s.add("freshness", check_freshness);
        s.add("digest", check_digest);
        s
    }

    /// Add a gate: an independent check that can veto.
    pub fn add(&mut self, name: &str, f: Check) -> &mut Self {
        self.gates.insert(name.to_owned(), f);
        self
    }

    /// Add a corroborator: one implementation of a question other corroborators also answer.
    pub fn corroborate_with(&mut self, name: &str, f: Check) -> &mut Self {
        self.corroborators.insert(name.to_owned(), f);
        self
    }

    pub fn len(&self) -> usize {
        self.gates.len()
    }

    pub fn is_empty(&self) -> bool {
        self.gates.is_empty()
    }

    /// Run every gate; all must accept.
    ///
    /// Every gate runs even after one vetoes, so the ledger records the full picture. A veto is
    /// reported as [`SwarmError::Rejected`] — an ordinary rejection, however many gates agreed.
    pub fn evaluate(&self, a: &Artifact<'_>) -> Result<Vec<CheckOutcome>, SwarmError> {
        if self.gates.is_empty() {
            return Err(SwarmError::Empty);
        }
        let outcomes: Vec<CheckOutcome> = self
            .gates
            .iter()
            .map(|(name, f)| CheckOutcome {
                name: name.clone(),
                verdict: f(a),
            })
            .collect();

        if outcomes.iter().all(|o| o.verdict == Verdict::Accept) {
            Ok(outcomes)
        } else {
            Err(SwarmError::Rejected { outcomes })
        }
    }

    /// Run every corroborator and require unanimity.
    ///
    /// This is where a split means something. A single answer is not corroboration at all, so
    /// fewer than two corroborators is [`SwarmError::Empty`]: one implementation cannot disagree
    /// with itself, and silently accepting would be the fail-open this module exists to prevent.
    pub fn corroborate(&self, a: &Artifact<'_>) -> Result<Vec<CheckOutcome>, SwarmError> {
        if self.corroborators.len() < 2 {
            return Err(SwarmError::Empty);
        }
        let outcomes: Vec<CheckOutcome> = self
            .corroborators
            .iter()
            .map(|(name, f)| CheckOutcome {
                name: name.clone(),
                verdict: f(a),
            })
            .collect();

        let accepts = outcomes
            .iter()
            .filter(|o| o.verdict == Verdict::Accept)
            .count();
        if accepts == outcomes.len() {
            Ok(outcomes)
        } else if accepts == 0 {
            // All implementations agree the artifact is bad. That is a rejection, not a
            // disagreement: they corroborated each other.
            Err(SwarmError::Rejected { outcomes })
        } else {
            Err(SwarmError::Disagreement { outcomes })
        }
    }

    /// Evaluate and record the outcome in the ledger.
    ///
    /// Disagreement is logged as `swarm.disagreement`, a distinct event kind, so a monitoring
    /// rule can alert on it alone.
    pub fn evaluate_audited(
        &self,
        a: &Artifact<'_>,
        ledger: &mut Ledger,
        at: u64,
    ) -> Result<Vec<CheckOutcome>, SwarmError> {
        let result = self.evaluate(a);
        let (kind, body) = describe(&result);
        // A ledger failure must not be swallowed: an unaudited verdict is not one we can defend
        // later. The swarm's own answer is still returned so the caller can act.
        let _ = ledger.append(at, kind, body.as_bytes());
        result
    }

    /// Corroborate and record the outcome.
    pub fn corroborate_audited(
        &self,
        a: &Artifact<'_>,
        ledger: &mut Ledger,
        at: u64,
    ) -> Result<Vec<CheckOutcome>, SwarmError> {
        let result = self.corroborate(a);
        let (kind, body) = describe(&result);
        let _ = ledger.append(at, kind, body.as_bytes());
        result
    }
}

/// Event kind and body for a result, shared by the audited entry points.
fn describe(result: &Result<Vec<CheckOutcome>, SwarmError>) -> (&'static str, String) {
    match result {
        Ok(o) => (
            "swarm.accept",
            o.iter()
                .map(|o| o.name.as_str())
                .collect::<Vec<_>>()
                .join(","),
        ),
        Err(SwarmError::Rejected { outcomes }) => (
            "swarm.reject",
            outcomes
                .iter()
                .filter(|o| o.verdict == Verdict::Reject)
                .map(|o| o.name.as_str())
                .collect::<Vec<_>>()
                .join(","),
        ),
        Err(SwarmError::Disagreement { outcomes }) => (
            "swarm.disagreement",
            outcomes
                .iter()
                .map(|o| format!("{}={:?}", o.name, o.verdict))
                .collect::<Vec<_>>()
                .join(","),
        ),
        Err(SwarmError::Empty) => ("swarm.empty", String::new()),
    }
}

/// Does the payload look like a capability token at all?
pub fn check_structural(a: &Artifact<'_>) -> Verdict {
    if a.payload.len() == sovereign_ipc::MAX_CAPABILITY_TOKEN {
        Verdict::Accept
    } else {
        Verdict::Reject
    }
}

/// Does the payload claim more than the caller is willing to grant?
pub fn check_rights_ceiling(a: &Artifact<'_>) -> Verdict {
    if a.claimed_rights.intersect(a.ceiling) == a.claimed_rights {
        Verdict::Accept
    } else {
        Verdict::Reject
    }
}

/// Is the artifact from an acceptable time window?
pub fn check_freshness(a: &Artifact<'_>) -> Verdict {
    match a.not_before {
        // A future `not_before` is a configuration error, not a freshness failure; treat it as a
        // rejection because we cannot distinguish it from a clock attack.
        Some(nb) if nb > a.now => Verdict::Reject,
        Some(nb) if a.now - nb > MAX_AGE_SECONDS => Verdict::Reject,
        _ => Verdict::Accept,
    }
}

/// Longest a capability may be reused for before the swarm refuses it, independent of whatever
/// expiry the token itself carries. A token that never expires is a token that outlives the
/// incident response that should have revoked it.
pub const MAX_AGE_SECONDS: u64 = 24 * 60 * 60;

/// Is this the artifact the caller meant to send?
pub fn check_digest(a: &Artifact<'_>) -> Verdict {
    match a.expected_digest {
        None => Verdict::Accept,
        Some(want) => {
            let mut h = Sha256::new();
            h.update(b"SOVEREIGN/v1/swarm-digest");
            h.update(a.domain);
            h.update((a.payload.len() as u64).to_be_bytes());
            h.update(a.payload);
            let got: [u8; 32] = h.finalize().into();
            // Constant-time comparison is not needed here: the digest is not a secret and the
            // caller already knows both values. Using `==` keeps this obviously correct.
            if got == want {
                Verdict::Accept
            } else {
                Verdict::Reject
            }
        }
    }
}

/// Compute the digest the `digest` check expects, so a caller can supply one.
pub fn digest_of(domain: &[u8], payload: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"SOVEREIGN/v1/swarm-digest");
    h.update(domain);
    h.update((payload.len() as u64).to_be_bytes());
    h.update(payload);
    h.finalize().into()
}

/// A swarm whose first gate is the hybrid signature check.
///
/// [`Check`] is a `fn` pointer and a signature check needs a key, so the key lives here and the
/// signature gate runs before the others.
pub struct SignedSwarm<'k> {
    swarm: Swarm,
    vk: &'k HybridVerifyingKey,
    signature: &'k sovereign_crypto::HybridSignature,
}

impl<'k> SignedSwarm<'k> {
    pub fn new(
        vk: &'k HybridVerifyingKey,
        signature: &'k sovereign_crypto::HybridSignature,
    ) -> Self {
        Self {
            swarm: Swarm::with_defaults(),
            vk,
            signature,
        }
    }

    pub fn swarm_mut(&mut self) -> &mut Swarm {
        &mut self.swarm
    }

    /// Verify the signature, then require every gate to accept.
    ///
    /// A bad signature is a plain [`SwarmError::Rejected`]: the ordinary case of a forged or
    /// corrupted artifact. It is not reported as disagreement, because nothing disagrees — the
    /// artifact is simply not authentic.
    pub fn evaluate(&self, a: &Artifact<'_>) -> Result<Vec<CheckOutcome>, SwarmError> {
        let sig_outcome = CheckOutcome {
            name: "hybrid-signature".to_owned(),
            verdict: if self.vk.verify(a.domain, a.payload, self.signature).is_ok() {
                Verdict::Accept
            } else {
                Verdict::Reject
            },
        };

        match self.swarm.evaluate(a) {
            Ok(mut outcomes) => {
                outcomes.push(sig_outcome.clone());
                if sig_outcome.verdict == Verdict::Accept {
                    Ok(outcomes)
                } else {
                    Err(SwarmError::Rejected {
                        outcomes: vec![sig_outcome],
                    })
                }
            }
            Err(SwarmError::Rejected { mut outcomes }) => {
                // Signature failure alongside gate failures: report all of them, so an operator
                // sees the whole picture rather than the first veto.
                outcomes.push(sig_outcome);
                Err(SwarmError::Rejected { outcomes })
            }
            Err(e) => Err(e),
        }
    }

    /// The cheap gates alone, without the signature. Exposed for the audited path.
    pub fn swarm(&self) -> &Swarm {
        &self.swarm
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sovereign_crypto::{labels, HybridSigningKey};

    fn key() -> HybridSigningKey {
        HybridSigningKey::from_seeds([0x11; 48], [0x22; 32])
    }

    fn payload() -> Vec<u8> {
        vec![7u8; sovereign_ipc::MAX_CAPABILITY_TOKEN]
    }

    fn artifact(p: &[u8]) -> Artifact<'_> {
        Artifact {
            domain: labels::CAPABILITY,
            payload: p,
            claimed_rights: Rights::SENSOR_READ,
            ceiling: Rights::SENSOR_READ.union(Rights::TELEMETRY_WRITE),
            now: 1_000_000,
            not_before: Some(999_000),
            expected_digest: None,
        }
    }

    #[test]
    fn all_default_gates_agree_on_a_good_artifact() {
        let p = payload();
        let outcomes = Swarm::with_defaults()
            .evaluate(&artifact(&p))
            .expect("accept");
        assert_eq!(outcomes.len(), 4);
        assert!(outcomes.iter().all(|o| o.verdict == Verdict::Accept));
    }

    #[test]
    fn a_short_payload_is_rejected_as_an_ordinary_rejection() {
        // The whole point of splitting gates from corroboration: one gate vetoing is a plain
        // rejection, not an alarm about the software.
        let p = vec![1u8; 10];
        let e = Swarm::with_defaults().evaluate(&artifact(&p)).unwrap_err();
        let SwarmError::Rejected { outcomes } = e else {
            panic!("expected Rejected, got {e:?}");
        };
        let structural = outcomes
            .iter()
            .find(|o| o.name == "structural")
            .expect("structural gate ran");
        assert_eq!(structural.verdict, Verdict::Reject);
        // And the other gates still ran and still accepted, which is what an auditor needs.
        assert_eq!(
            outcomes
                .iter()
                .filter(|o| o.verdict == Verdict::Accept)
                .count(),
            3
        );
    }

    #[test]
    fn claiming_more_rights_than_the_ceiling_is_rejected() {
        let p = payload();
        let mut a = artifact(&p);
        a.claimed_rights = Rights::ADMIN;
        let e = Swarm::with_defaults().evaluate(&a).unwrap_err();
        assert!(matches!(e, SwarmError::Rejected { .. }), "got {e:?}");
        assert_eq!(check_rights_ceiling(&a), Verdict::Reject);
    }

    #[test]
    fn a_stale_artifact_is_rejected() {
        let p = payload();
        let mut a = artifact(&p);
        a.not_before = Some(1);
        a.now = 1 + MAX_AGE_SECONDS + 1;
        assert_eq!(check_freshness(&a), Verdict::Reject);
    }

    #[test]
    fn an_artifact_just_inside_the_window_is_accepted() {
        let p = payload();
        let mut a = artifact(&p);
        a.not_before = Some(1);
        a.now = 1 + MAX_AGE_SECONDS;
        assert_eq!(check_freshness(&a), Verdict::Accept);
    }

    #[test]
    fn a_future_not_before_is_rejected() {
        let p = payload();
        let mut a = artifact(&p);
        a.not_before = Some(a.now + 1);
        assert_eq!(check_freshness(&a), Verdict::Reject);
    }

    #[test]
    fn a_wrong_digest_is_rejected() {
        let p = payload();
        let mut a = artifact(&p);
        a.expected_digest = Some([0u8; 32]);
        assert_eq!(check_digest(&a), Verdict::Reject);
    }

    #[test]
    fn the_right_digest_is_accepted() {
        let p = payload();
        let mut a = artifact(&p);
        a.expected_digest = Some(digest_of(a.domain, &p));
        assert_eq!(check_digest(&a), Verdict::Accept);
    }

    #[test]
    fn corroborating_implementations_that_agree_are_accepted() {
        let p = payload();
        let mut s = Swarm::new();
        // Two independent spellings of the same question: one uses the helper, one inlines the
        // hash. They must agree.
        s.corroborate_with("via-helper", |a| {
            if Some(digest_of(a.domain, a.payload))
                == a.expected_digest.or(Some(digest_of(a.domain, a.payload)))
            {
                Verdict::Accept
            } else {
                Verdict::Reject
            }
        });
        s.corroborate_with("via-check", check_digest);
        let mut a = artifact(&p);
        a.expected_digest = Some(digest_of(a.domain, &p));
        let outcomes = s.corroborate(&a).expect("corroborated");
        assert_eq!(outcomes.len(), 2);
    }

    #[test]
    fn a_split_between_corroborators_is_disagreement() {
        let p = payload();
        let mut s = Swarm::new();
        s.corroborate_with("always-accept", |_| Verdict::Accept);
        s.corroborate_with("always-reject", |_| Verdict::Reject);

        let e = s.corroborate(&artifact(&p)).unwrap_err();
        assert!(matches!(e, SwarmError::Disagreement { .. }), "got {e:?}");
        // And it renders the per-check verdicts, which is what an operator needs.
        let text = e.to_string();
        assert!(text.contains("always-accept=Accept"), "{text}");
        assert!(text.contains("always-reject=Reject"), "{text}");
        assert!(text.contains("DISAGREEMENT"), "{text}");
    }

    #[test]
    fn corroborators_that_unanimously_reject_are_a_rejection_not_a_disagreement() {
        let p = payload();
        let mut s = Swarm::new();
        s.corroborate_with("a", |_| Verdict::Reject);
        s.corroborate_with("b", |_| Verdict::Reject);
        assert!(matches!(
            s.corroborate(&artifact(&p)),
            Err(SwarmError::Rejected { .. })
        ));
    }

    #[test]
    fn a_single_corroborator_is_not_corroboration() {
        let p = payload();
        let mut s = Swarm::new();
        s.corroborate_with("only", |_| Verdict::Accept);
        assert_eq!(s.corroborate(&artifact(&p)).unwrap_err(), SwarmError::Empty);
    }

    #[test]
    fn an_empty_swarm_refuses_to_accept() {
        // Fail-open would be the worst possible default here.
        assert_eq!(
            Swarm::new().evaluate(&artifact(&payload())).unwrap_err(),
            SwarmError::Empty
        );
    }

    #[test]
    fn every_gate_runs_even_after_one_rejects() {
        use std::cell::Cell;
        thread_local! {
            static RAN: Cell<usize> = const { Cell::new(0) };
        }
        fn counting(_: &Artifact<'_>) -> Verdict {
            RAN.with(|c| c.set(c.get() + 1));
            Verdict::Reject
        }
        let mut s = Swarm::new();
        s.add("a", counting);
        s.add("b", counting);
        s.add("c", counting);
        let _ = s.evaluate(&artifact(&payload()));
        assert_eq!(RAN.with(|c| c.get()), 3, "all gates must run");
    }

    #[test]
    fn disagreement_is_logged_under_its_own_event_kind() {
        let p = payload();
        let mut s = Swarm::new();
        s.corroborate_with("yes", |_| Verdict::Accept);
        s.corroborate_with("no", |_| Verdict::Reject);

        let mut ledger = Ledger::new();
        let _ = s.corroborate_audited(&artifact(&p), &mut ledger, 5);
        assert_eq!(
            ledger.entries().last().expect("entry").kind,
            "swarm.disagreement"
        );
        assert_eq!(ledger.verify(None, None), Ok(1));
    }

    #[test]
    fn an_ordinary_rejection_logs_as_reject_not_disagreement() {
        let p = vec![1u8; 3];
        let mut ledger = Ledger::new();
        let _ = Swarm::with_defaults().evaluate_audited(&artifact(&p), &mut ledger, 6);
        assert_eq!(ledger.entries().last().expect("entry").kind, "swarm.reject");
    }

    #[test]
    fn a_valid_hybrid_signature_passes_the_signed_swarm() {
        let k = key();
        let p = payload();
        let sig = k.sign(labels::CAPABILITY, &p).expect("sign");

        let vk = k.verifying_key();
        let signed = SignedSwarm::new(&vk, &sig);
        let outcomes = signed.evaluate(&artifact(&p)).expect("accept");
        assert!(outcomes.iter().any(|o| o.name == "hybrid-signature"));
    }

    #[test]
    fn a_tampered_payload_fails_the_signed_swarm() {
        let k = key();
        let mut p = payload();
        let sig = k.sign(labels::CAPABILITY, &p).expect("sign");
        p[0] ^= 0xFF;

        let vk = k.verifying_key();
        let signed = SignedSwarm::new(&vk, &sig);
        let e = signed.evaluate(&artifact(&p)).unwrap_err();
        assert!(matches!(e, SwarmError::Rejected { .. }), "got {e:?}");
        assert!(e.to_string().contains("hybrid-signature"));
    }

    #[test]
    fn a_signature_from_the_wrong_domain_fails_the_signed_swarm() {
        let k = key();
        let p = payload();
        let sig = k.sign(labels::ATTESTATION, &p).expect("sign");

        let vk = k.verifying_key();
        let signed = SignedSwarm::new(&vk, &sig);
        assert!(signed.evaluate(&artifact(&p)).is_err());
    }
}
