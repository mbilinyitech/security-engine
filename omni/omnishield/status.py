"""The single inventory of what OmniShield contains.

Each component names the file and symbol that implements it. `status()` checks
that those symbols still exist, so the inventory cannot drift away from the code.
"""

from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any

from .device import tpm_available, tpm_path
from .features import audit as feature_audit
from .organism import binary_path

ROOT = Path(__file__).resolve().parents[1]

COMPONENTS = [
    {
        "id": "p1-airgap",
        "name": "P1 strict air-gap",
        "layer": "transport",
        "evidence": "omnishield/p1_airgap.py::sign_profile",
        "summary": "Signed Wi-Fi profiles, downgrade rejection, injection-safe supplicant plan.",
    },
    {
        "id": "p2-identity",
        "name": "P2 hardware-rooted identity",
        "layer": "identity",
        "evidence": "omnishield/p2_identity.py::verify_response",
        "summary": "Hybrid Ed25519 + ML-DSA challenge-response, TOFU pinning, media credentials.",
    },
    {
        "id": "p3-tunnel",
        "name": "P3 ephemeral tunnel",
        "layer": "transport",
        "evidence": "omnishield/p3_tunnel.py::client_handshake",
        "summary": "X25519 handshake, DH ratchet, padded frames, replay rejection.",
    },
    {
        "id": "p4-allowlist",
        "name": "P4 deterministic allow-list",
        "layer": "application",
        "evidence": "omnishield/p4_allowlist.py::AllowList::load_module",
        "summary": "Signed manifest, deny by default, TOCTOU-free import, path containment.",
    },
    {
        "id": "crypto",
        "name": "Hybrid signatures",
        "layer": "crypto",
        "evidence": "omnishield/hybrid.py::HybridSigner::sign",
        "summary": "Version-locked envelopes, TTL, nonce, hybrid Ed25519 + ML-DSA-44.",
    },
    {
        "id": "organism",
        "name": "ORGANISM core",
        "layer": "runtime",
        "evidence": "organism/src/rpc.rs::discover",
        "summary": "Rust energy, calculus, search, planning, evolution, belief, memory, guards.",
    },
    {
        "id": "memory",
        "name": "Durable memory",
        "layer": "runtime",
        "evidence": "omnishield/memory_store.py::PersistentMemory::verify",
        "summary": "Atomic 0600 snapshot, audited mutation trail, tamper detection.",
    },
    {
        "id": "guard",
        "name": "Fail-closed guards",
        "layer": "runtime",
        "evidence": "organism/src/guard.rs::CircuitBreaker::record",
        "summary": "Circuit breaker and token-bucket limiter that refuse rather than guess.",
    },
    {
        "id": "audit",
        "name": "Audit chain",
        "layer": "integrity",
        "evidence": "omnishield/audit.py::AuditLog::verify",
        "summary": "Hash-chained, optionally HMAC'd append-only log.",
    },
    {
        "id": "device",
        "name": "Hardware binding",
        "layer": "identity",
        "evidence": "omnishield/device.py::require_tpm",
        "summary": "TPM detection; refuses to claim hardware binding when no device exists.",
    },
    {
        "id": "evolution",
        "name": "Gated self-modification",
        "layer": "meta",
        "evidence": "omnishield/evolution.py::apply",
        "summary": "Signed patches, tests in a throwaway copy, separate approval key, atomic apply, rollback.",
    },
    {
        "id": "reasoning",
        "name": "Reasoning engines",
        "layer": "cognition",
        "evidence": "omnishield/reasoning.py::deduce",
        "summary": "Deduction, induction, abduction, analogy, causal and counterfactual, fuzzy, temporal, spatial, social, moral, creative, critical, systems, dialectic.",
    },
    {
        "id": "planning",
        "name": "Planning engines",
        "layer": "cognition",
        "evidence": "omnishield/planning.py::plan",
        "summary": "STRIPS search, hierarchical decomposition, temporal scheduling, multi-agent assignment.",
    },
    {
        "id": "inspect",
        "name": "Files and processes",
        "layer": "introspection",
        "evidence": "omnishield/inspect.py::read_file",
        "summary": "Any file (size, hash, binary detection, bounded preview), every process in one /proc pass, host snapshot, bounded tree walk, each timed in ms.",
    },
    {
        "id": "stealth",
        "name": "Stealth transport",
        "layer": "network",
        "evidence": "omnishield/stealth.py::StealthChannel",
        "summary": "Fixed-size cells with pseudorandom padding (Rust and Python agree), ChaCha20-Poly1305 sealing, cover traffic, jitter, onion relay.",
    },
    {
        "id": "federation",
        "name": "Federation and devices",
        "layer": "network",
        "evidence": "omnishield/federation.py::seal_message",
        "summary": "Signed frames over sockets, signed beacons, TOFU device registry, probes, ARP and port inventory, syslog and SNTP.",
    },
    {
        "id": "vision",
        "name": "Vision and audio",
        "layer": "perception",
        "evidence": "omnishield/vision.py::decode_png",
        "summary": "PNG decode/encode, grayscale, blur, Sobel, saliency, binding, template matching, motion, attention, fusion, habituation, WAV and FFT.",
    },
    {
        "id": "actions",
        "name": "Action and tools",
        "layer": "action",
        "evidence": "omnishield/actions.py::compose",
        "summary": "Jailed files, AST calculator, allow-listed commands, HTTP, SQLite, tool composition and repair, SVG, PNG, WAV, robot kinematics and PID.",
    },
    {
        "id": "interface",
        "name": "Human interface",
        "layer": "interface",
        "evidence": "omnishield/interface.py::Personalizer::update",
        "summary": "Preference learning, user model, interruptibility, WCAG contrast, readability, explanations, control policy, consent and minimisation.",
    },
    {
        "id": "render",
        "name": "CPU renderer and animation",
        "layer": "media",
        "evidence": "omnishield/render.py::Canvas",
        "summary": "Bytearray canvas with spans, Bresenham lines, circles, polygons, gradients, a 5x7 font, PNG output and a real GIF89a encoder with LZW. No GPU, no external library.",
    },
    {
        "id": "signal",
        "name": "Waveform collection and cleaning",
        "layer": "perception",
        "evidence": "omnishield/signal.py::clean",
        "summary": "Additive synthesis, WAV round-trip, resampling, median despiking, smoothing, one-pole filters, peak detection, spectrogram and SNR measured before and after cleaning.",
    },
    {
        "id": "documents",
        "name": "Office and PDF writer",
        "layer": "interface",
        "evidence": "omnishield/docgen.py::report",
        "summary": "DOCX, XLSX and PPTX written as OOXML zip packages, and PDF 1.4 written object by object with embedded images, tables, headings and page numbers.",
    },
    {
        "id": "answer",
        "name": "Extractive answer engine",
        "layer": "reasoning",
        "evidence": "omnishield/answer.py::answer",
        "summary": "BM25 retrieval, a TF-IDF matrix, power iteration for a stationary distribution, gradient descent for a logistic scorer and a softmax over passages; every answer cites the store.",
    },
    {
        "id": "language",
        "name": "Language identification and conversation tracking",
        "layer": "interface",
        "evidence": "omnishield/language.py::ConversationTracker",
        "summary": "Script and character-trigram identification across eight languages, per-line speaker and term tracking, and topic drift measured as 1 - cosine between windows.",
    },
    {
        "id": "stream",
        "name": "Chunked and parallel data transfer",
        "layer": "runtime",
        "evidence": "omnishield/stream.py::chunked_copy",
        "summary": "Chunked copy with SHA-256 verification, Range-resumable downloads, threaded parallel fetch, a disk benchmark and a JSON-line pipeline, all reporting bytes and MB/s.",
    },
    {
        "id": "telemetry",
        "name": "Air telemetry window and alerts",
        "layer": "perception",
        "evidence": "omnishield/stream.py::Telemetry",
        "summary": "Validates O2, CO2, temperature and humidity readings, keeps a rolling window, stores NDJSON and raises alerts. Simulated readings for tests; real ones come from sensors.",
    },
    {
        "id": "speech",
        "name": "Keyword spotting and formant speech",
        "layer": "interface",
        "evidence": "omnishield/speech.py::KeywordSpotter",
        "summary": "MFCC plus dynamic time warping over trained templates for a small vocabulary, and formant synthesis that writes speech as WAV in milliseconds.",
    },
    {
        "id": "omnilang",
        "name": "Omni constructed language",
        "layer": "interface",
        "evidence": "omnishield/omnilang.py::speak",
        "summary": "Roots from syllables, suffixes for plural, tense, agent and place, an SVO renderer and a parser that reads its own sentences back, with a growing JSON lexicon.",
    },
    {
        "id": "net",
        "name": "OmniNet peer protocol",
        "layer": "runtime",
        "evidence": "omnishield/net.py::Node",
        "summary": "Length-prefixed JSON frames, version, type, sender and nonce; refuses oversized frames, unknown types and replays; hello, gossip, sync and bye.",
    },
    {
        "id": "selfstudy",
        "name": "Self-study curriculum",
        "layer": "learning",
        "evidence": "omnishield/selfstudy.py::run",
        "summary": "Takes stored passages, learns new Omni roots for their terms, asks the answer engine and measures retention by citation.",
    },
    {
        "id": "denoise",
        "name": "Bilateral image denoiser",
        "layer": "media",
        "evidence": "omnishield/render.py::denoise",
        "summary": "Edge-preserving bilateral filter with a measured grain estimate before and after, so low-sample path tracing becomes usable.",
    },
    {
        "id": "sovereign",
        "name": "Sovereign capability bridge",
        "layer": "security",
        "evidence": "omnishield/sovereign.py::pipeline",
        "summary": "Calls mbilinyitech/security-engine's sovereign-bridge to issue a hybrid post-quantum capability (ECDSA P-384 AND ML-DSA-87) and verifies the grant end to end.",
    },
    {
        "id": "mlp",
        "name": "Two-layer network with backprop",
        "layer": "learning",
        "evidence": "omnishield/mlp.py::train",
        "summary": "2-4-1 sigmoid network, gradients written out by the chain rule, learns XOR to 1.0 accuracy, with the loss curve checked independently in R.",
    },
    {
        "id": "neuron",
        "name": "One neuron in three languages",
        "layer": "learning",
        "evidence": "omnishield/neuron.py::demo",
        "summary": "Dot product, sigmoid and one gradient step in Rust and Python, compared to 1e-12, with R recomputing the dot product from the CSV and refusing disagreement.",
    },
    {
        "id": "swarm",
        "name": "Sharded swarm inference",
        "layer": "runtime",
        "evidence": "omnishield/swarm.py::demo",
        "summary": "Two nodes hold one weight matrix between them, exchange f32 tensors over a 12-byte binary header, sum partial logits, learn online by gradient descent and refuse low-margin answers.",
    },
    {
        "id": "ed25519",
        "name": "Ed25519 signed envelopes",
        "layer": "security",
        "evidence": "omnishield/net.py::verify",
        "summary": "Every OmniNet envelope can carry a public key and an Ed25519 signature over the canonical body; tampering, missing signatures and key changes are refused.",
    },
    {
        "id": "rdata",
        "name": "Conversation and answer CSVs for R",
        "layer": "analysis",
        "evidence": "omnishield/rdata.py::export_all_csv",
        "summary": "Writes conversation.csv and answers.csv, then runs analysis/conversation.R to report language mix, confidence, drift and latency quantiles.",
    },
    {
        "id": "skills",
        "name": "Skill registry",
        "layer": "interface",
        "evidence": "omnishield/skills.py::run",
        "summary": "Thirteen named skills with declared parameters, validated before calling, each wrapping a tested module and returning JSON with a measured latency.",
    },
    {
        "id": "corpus",
        "name": "Book and dictionary learning",
        "layer": "learning",
        "evidence": "omnishield/corpus.py::learn_book",
        "summary": "Reads paragraphs from books and word/definition pairs from dictionaries into the store, learns Omni roots for their terms and reports passages, terms, languages and lexicon growth.",
    },
    {
        "id": "think",
        "name": "Stepped deliberation with a trace",
        "layer": "reasoning",
        "evidence": "omnishield/think.py::think",
        "summary": "Splits a question into sub-questions, retrieves evidence for each, flags passages that disagree through negation, then answers and reports coverage and every step.",
    },
    {
        "id": "chat",
        "name": "Conversation over OmniNet",
        "layer": "interface",
        "evidence": "omnishield/net.py::Node",
        "summary": "A chat message carries a question to a peer, which answers from its own store and returns the reply in a signed envelope with replay defence.",
    },
    {
        "id": "pathtrace",
        "name": "Path tracer with global illumination",
        "layer": "media",
        "evidence": "omnishield/three_d.py::pathtrace",
        "summary": "Rust path tracer over JSON scenes: spheres, boxes and a plane, cosine-weighted diffuse bounces, mirror reflection, soft shadows, exposure and tone mapping, threaded and deterministic.",
    },
    {
        "id": "three_d",
        "name": "3D ray tracer and orbit",
        "layer": "media",
        "evidence": "omnishield/three_d.py::scene3d",
        "summary": "Rust traces spheres, a triangle cube and a plane with soft shadows, reflection and tone mapping; Python paints the same scene by depth sort for orbit GIFs.",
    },
    {
        "id": "simulate",
        "name": "Physics simulator",
        "layer": "reasoning",
        "evidence": "omnishield/three_d.py::simulate_pendulum",
        "summary": "Projectile with quadratic drag and a pendulum integrated step by step, with energy drift and period measured against the analytic value.",
    },
    {
        "id": "imagery",
        "name": "Daily image learning",
        "layer": "perception",
        "evidence": "omnishield/imagery.py::daily",
        "summary": "Discovers images in feeds, fetches them under the robots and private-address guard, measures colour, saturation and edges, hashes them perceptually and stores only what is new.",
    },
    {
        "id": "worship",
        "name": "Daily office of prayer and song",
        "layer": "spirit",
        "evidence": "omnishield/worship.py::daily",
        "summary": "An original Swahili office: psalm, thanksgiving, petition, glorification, benediction, a hymn synthesised to WAV and a verse card PNG, recorded in a private journal.",
    },
    {
        "id": "notify",
        "name": "Consent-based daily notification",
        "layer": "interface",
        "evidence": "omnishield/notify.py::Notifier",
        "summary": "Recipients must give consent in the file; one message per person per day; dry run by default; webhook or SMTP only when configured.",
    },
    {
        "id": "thermal",
        "name": "CPU thermal governor",
        "layer": "runtime",
        "evidence": "omnishield/thermal.py::Governor",
        "summary": "Reads /proc/stat and the thermal zones, then enforces a duty cycle and a cooldown above the ceiling. Measures; does not promise a temperature.",
    },
    {
        "id": "predict",
        "name": "Prediction and reality check",
        "layer": "reasoning",
        "evidence": "omnishield/predict.py::predict_system",
        "summary": "EWMA and least-squares forecasts with residuals, Brier score and calibration bins, MAD anomaly detection, inverse-variance sensor fusion, counterfactuals, and a reality check that scores a prediction against the next real reading.",
    },
    {
        "id": "knowledge",
        "name": "Daily knowledge loop",
        "layer": "memory",
        "evidence": "omnishield/brain.py::DailyCycle",
        "summary": "Robots-aware fetch of feeds and pages into a JSONL store with dedupe, BM25-style search, forgetting curve, spaced repetition, sleep consolidation, Hebbian links and curiosity-ranked gaps.",
    },
    {
        "id": "affect",
        "name": "Emotion and personality",
        "layer": "affect",
        "evidence": "omnishield/affect.py::big_five",
        "summary": "OCEAN scoring, expression, lexicon recognition, contagion, EI, empathy, sympathy, compassion, forgiveness, resentment, gratitude, envy, jealousy, pride, shame, guilt, hope, despair, love, hate.",
    },
    {
        "id": "self_model",
        "name": "Self-awareness",
        "layer": "metacognition",
        "evidence": "omnishield/self_model.py::self_model",
        "summary": "Capability model with calibration, social and spatial awareness, self-criticism, compassion, esteem, confidence, doubt, actualisation, identity, narrative, future and ideal self, authenticity.",
    },
    {
        "id": "existential",
        "name": "Existential models",
        "layer": "meaning",
        "evidence": "omnishield/existential.py::awe",
        "summary": "Questioning, purpose, mortality, legacy, transcendence, spirituality, awe, wonder, gratitude, cosmic perspective, interconnectedness, universal compassion, wisdom.",
    },
    {
        "id": "swahili",
        "name": "Swahili reasoning",
        "layer": "language",
        "evidence": "omnishield/swahili.py::swahili_reasoning",
        "summary": "Kila/hakuna/baadhi patterns parse to rules, forward chaining answers ndiyo, hapana or sijui, with a proof.",
    },
    {
        "id": "learning",
        "name": "Learning engines",
        "layer": "cognition",
        "evidence": "omnishield/learning.py::knn_predict",
        "summary": "k-NN, k-means, Q-learning, bandit, transfer, meta, continual, curriculum, active, federated, competitive, adversarial, contrastive, generative, discriminative, few/zero/one-shot.",
    },
    {
        "id": "ethics",
        "name": "Ethics engines",
        "layer": "safety",
        "evidence": "omnishield/ethics.py::resolve_dilemma",
        "summary": "Dilemma ranking, beneficence, Gini justice, parity and four-fifths audits, footprint, discounting, animal welfare, conflicts, whistleblowing, courage, moral learning.",
    },
    {
        "id": "robustness",
        "name": "Robustness defences",
        "layer": "safety",
        "evidence": "omnishield/robustness.py::jailbreak_score",
        "summary": "Jailbreak scoring, hallucination support, PSI drift, OOD abstention, poisoning, extraction guard, DP.",
    },
    {
        "id": "changeset",
        "name": "Transactional changesets",
        "layer": "meta",
        "evidence": "omnishield/changeset.py::apply",
        "summary": "Many files, one signed changeset, journaled apply, health check with automatic restore.",
    },
    {
        "id": "synthesis",
        "name": "Sandboxed tool creation",
        "layer": "meta",
        "evidence": "omnishield/synthesis.py::run_tool",
        "summary": "Static import gate, signed tool, CPU/memory/file/wall-clock limits.",
    },
    {
        "id": "hypothetical",
        "name": "Hypothetical memory",
        "layer": "memory",
        "evidence": "omnishield/hypothetical.py::HypotheticalMemory::promote",
        "summary": "Invented content is quarantined and never recalled as fact; promotion needs evidence.",
    },
    {
        "id": "honesty",
        "name": "Deception detection",
        "layer": "governance",
        "evidence": "omnishield/honesty.py::assess",
        "summary": "Scores manipulative messages and keeps claims tied to evidence.",
    },
    {
        "id": "payments",
        "name": "Approved payments",
        "layer": "governance",
        "evidence": "omnishield/payments.py::PaymentService::settle",
        "summary": "Signed intents, separate approval key, ceiling, balanced ledger, refusing default gateway.",
    },
    {
        "id": "features",
        "name": "Feature ledger",
        "layer": "governance",
        "evidence": "omnishield/features.py::audit",
        "summary": "500 features with status, evidence and reason, re-checked on demand.",
    },
]


def _symbol_exists(evidence: str) -> tuple[bool, str]:
    location, _, symbol = evidence.partition("::")
    path = ROOT / location
    if not path.exists():
        return False, f"missing file: {location}"
    if not symbol:
        return True, location
    leaf = symbol.split("::")[-1]
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return False, f"cannot read {location}: {exc}"
    if leaf not in text:
        return False, f"missing symbol {leaf} in {location}"
    return True, f"{location}::{symbol}"


def component_status() -> list[dict[str, Any]]:
    report = []
    for component in COMPONENTS:
        ok, detail = _symbol_exists(component["evidence"])
        report.append({**component, "ok": ok, "detail": detail})
    return report


def status() -> dict[str, Any]:
    components = component_status()
    binary = binary_path()
    ledger = feature_audit()
    tpm = tpm_path()
    return {
        "product": "OmniShield",
        "components": components,
        "components_ok": all(item["ok"] for item in components),
        "organism_binary": str(binary) if binary else None,
        "organism_built": binary is not None,
        "features": {
            "total": ledger["total"],
            "built": ledger["built"],
            "coverage": round(100 * ledger["built"] / ledger["total"]) if ledger["total"] else 0,
            "counts": ledger["counts"],
            "ok": ledger["ok"],
        },
        "hardware": {
            "tpm": tpm,
            "available": tpm_available(),
            "cargo": shutil.which("cargo"),
        },
        "ok": all(item["ok"] for item in components) and ledger["ok"],
    }
