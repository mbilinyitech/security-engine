# OmniShield

Four fail-closed layers for transport security, built as running code:

1. **Strict air-gap and anti-legacy** — a signed network profile plus a downgrade guard.
2. **Hardware-rooted identity** — challenge-response bound to a device key, TOFU pinning, content credentials.
3. **Ephemeral tunnel** — X25519 handshake with optional server authentication, per-frame AEAD, Diffie-Hellman ratchet, padded frames.
4. **Deterministic allow-list** — signed manifests, verified module loading, a behavioural timing gate.

Every layer is signed with a **hybrid Ed25519 + ML-DSA-44** signature. Both halves must verify; there is no fallback to the classical half. Envelopes carry a protocol version lock, an issuance window, and a single-use nonce.

```bash
python3 -m pip install -e .
python3 -m pytest          # 483 passed, 1 skipped (IPv6 loopback absent here)
cargo test --manifest-path organism/Cargo.toml   # 76 Rust tests
python3 -m omnishield.bench  # measured numbers, see below
```

## One product, one command

OmniShield is the product. Everything below lives inside it: the four transport
layers, the hybrid signature engine, the Rust organism core, durable memory, the
fail-closed guards, the audit chain, hardware binding and the feature ledger.

`status` proves that every component still points at live code. `doctor` runs
each layer for real — real signatures, a real socket, a real file, a real
subprocess — and exits non-zero if any layer fails.

```
$ omnishield status
OmniShield
  [ok ] P1 strict air-gap              omnishield/p1_airgap.py::sign_profile
  [ok ] P2 hardware-rooted identity    omnishield/p2_identity.py::verify_response
  [ok ] P3 ephemeral tunnel            omnishield/p3_tunnel.py::client_handshake
  [ok ] P4 deterministic allow-list    omnishield/p4_allowlist.py::AllowList::load_module
  [ok ] Hybrid signatures              omnishield/hybrid.py::HybridSigner::sign
  [ok ] ORGANISM core                  organism/src/rpc.rs::discover
  [ok ] Durable memory                 omnishield/memory_store.py::PersistentMemory::verify
  [ok ] Fail-closed guards             organism/src/guard.rs::CircuitBreaker::record
  [ok ] Audit chain                    omnishield/audit.py::AuditLog::verify
  [ok ] Hardware binding               omnishield/device.py::require_tpm
  [ok ] Feature ledger                 omnishield/features.py::audit
  organism binary: /workspace/project/organism/target/release/organism
  features: 398/500 built (80%)

$ omnishield doctor
  PASS  crypto             5 ms  Ed25519 + ML-DSA-44 envelope verified
  PASS  p1-airgap          1 ms  profile verified, wpa2-psk refused
  PASS  features           4 ms  500 features, 398 built, evidence valid
  PASS  hardware           0 ms  no TPM on this machine; hardware binding is refused by design
  PASS  p2-identity        5 ms  challenge answered, counter=1, device=e00f95f13432
  PASS  p3-tunnel          2 ms  handshake, ratcheted frame and reply verified
  PASS  p4-allowlist       1 ms  signed artifact loaded, tampered artifact refused
  PASS  organism           2 ms  energy=4.0, mean=0.667, breaker=open
  PASS  memory             6 ms  insert/search ok, snapshot f54bb69ec7e3…, tamper detected
  PASS  audit              0 ms  2 entries verified, tamper detected
  PASS  evolution        251 ms  review passed, approved by human:doctor, applied and backed up
  PASS  corpus            5 ms  2 definitions, 1 paragraphs, 12 terms, lexicon 12
  PASS  think             2 ms  coverage 0.5, 1 disagreement, 6 steps, 0.2 ms
  PASS  chat              7 ms  reply 61 chars, replay refused
  PASS  omnilang          3 ms  fofar xa gotu puke -> person see sun [past]; 5 roots
  PASS  net               6 ms  hello from beta, gossip ok 1, beta items 1, replay refused
  PASS  selfstudy         3 ms  2 lessons, 6 new roots, hit rate 1.0
  PASS  denoise           9 ms  grain 8.4 -> 2.1, kept the edge at x=24
  PASS  pathtrace          8 ms  2560 pixels, 1 bounces, 2 threads, 0.559 ms, 2259 B PNG
  PASS  answer            9 ms  a cited at 1.03, matrix [3, 24], 0.06 ms
  PASS  language         13 ms  sw 1.0, en 0.92, zh by script; drift 0.52
  PASS  stream            51 ms  verified copy, disk write/read MB/s, pipeline items/s
  PASS  telemetry          1 ms  30 samples, O2 20.616%, CO2 912.287 ppm, 1 alerts
  PASS  speech           219 ms  0.52 s in 5.18 ms, habari d=12.17, asante d=0.0
  PASS  three_d           27 ms  perspective camera, painter sort, 4 orbit frames differ
  PASS  simulate           0 ms  projectile range 14.425 m, apex 3.585 m, energy change 1.6168 J; pendulum period 2.0413 s
  PASS  imagery          725 ms  aHash 7f677b5d7e7f0000 vs 7f3f5f6f77780000, distance 13, 5 colour blocks
  PASS  render_quality     7 ms  contrast 95.38, saturation 0.6515, 45 colours, PPM round-trip ok
  PASS  worship          351 ms  1970-01-04 imani, 26880 hymn samples, 5772 B verse card
  PASS  notify            22 ms  consent enforced, dry run logged, one message per day
  PASS  thermal           72 ms  usage 5%, temperature unavailable, duty 1.0
  PASS  render            12 ms  32x24 PNG decoded, 3-frame GIF with LZW, seeded art reproduced
  PASS  signal             4 ms  440 Hz kept, SNR 6.335 -> 10.461 dB, 988154 samples/s
  PASS  documents         24 ms  docx 2187 B, xlsx 2631 B, pptx 5112 B, pdf 1770 B with a page and a trailer
  PASS  predict            0 ms  slope 1.0 forecast 6/7, anomaly z 65.427, brier 0.01 below baseline 0.25, ece 0.1
  PASS  knowledge         31 ms  dedupe held, search ranked, review scheduled, feed parsed, robots obeyed, working memory 2 slots
  PASS  affect             0 ms  OCEAN openness dominant, joy recognised, love consummate, hope 0.7
  PASS  self_model         0 ms  calibration 0.2, nearest landmark box at 2.0, actualising with no unmet need
  PASS  existential        0 ms  purpose helping 0.72, awe 0.72, wisdom 0.825 (wise)
  PASS  swahili            0 ms  ndiyo proved in 1 step, hapana from a none rule, sijui kept unknown
  PASS  inspect            8 ms  file 0.096 ms, 36 processes in 1.574 ms, snapshot in 6.012 ms
  PASS  stealth            0 ms  3 cells of 540 bytes, cover dropped, 2-hop onion peeled in order
  PASS  federation         3 ms  signed frame verified, tamper refused, beacon pinned, ARP parsed
  PASS  vision             4 ms  PNG round trip exact, Sobel found the border, binding found one 16-pixel object
  PASS  actions           16 ms  calculator 14, sandbox round trip, SVG polyline, mean 2.5
  PASS  interface          0 ms  contrast 21.0:1 AAA, interrupt cost 0.225, preference ranked
  PASS  report            14 ms  schema 1.0.0, 62 components, 398 built, counts add up
  PASS  learning           6 ms  k-NN and k-means separated two clusters (inertia 0.02), perceptron reached 1.0, bandit found the 0.8 arm
  PASS  ethics             0 ms  parity fair, four-fifths flagged b, Gini 0.75, dilemma chose help
  PASS  reasoning          1 ms  proof found, cause ranked first, counterfactual moved z from 6 to 12
  PASS  planning           0 ms  3-step plan, 2 primitives, makespan 5.0, task assigned
  PASS  robustness         1 ms  jailbreak blocked, PSI 12.434, OOD abstained, budget 0.6 left
  PASS  changeset        539 ms  two files applied as one unit, failed health check restored them
  PASS  synthesis         27 ms  tool ran in 23 ms under process limits only
  PASS  hypothetical      24 ms  imagined content stayed out of recall, promotion required evidence
  PASS  honesty            5 ms  scam text scored 6.5, claim published only after evidence
  PASS  payments           7 ms  approved payment settled, ledger balanced, default gateway refused

63/63 checks passed in 2541 ms
```

The old `ohshield` command remains as an alias for `omnishield`.

## Machine-readable output

Every command that reports state can emit JSON, so CI jobs and other agents do
not have to parse prose.

| command | what it prints |
|---|---|
| `omnishield report` | one document: schema version, features, components, doctor, environment |
| `omnishield report --no-doctor` | the same document without the end-to-end checks (fast) |
| `omnishield report --out FILE` | writes the document to a file as well as stdout |
| `omnishield report --schema` | the JSON Schema the document validates against |
| `omnishield status --json` | components, binary path and ledger counts |
| `omnishield doctor --json` | every check with milliseconds and detail |
| `omnishield doctor --jsonl` | one JSON object per check, for log pipelines |
| `omnishield features audit --json` | totals, counts and problems |
| `omnishield features list --json [--status S] [--group G]` | feature records |
| `omnishield features show ID` | one record |
| `omnishield inspect file PATH --json` | size, sha256, binary flag and preview |
| `omnishield inspect processes --json` | every process, with the cost in ms |
| `omnishield inspect system --json` | host, cpu, memory, disk, thermal, ports |
| `omnishield federation inventory --json` | ARP neighbours and listening TCP ports |
| `omnishield federation probe HOST --port N` | TCP reachability, exit 0 only when open |
| `omnishield federation beacon --port N --capability X` | a signed device beacon |
| `omnishield export --out DIR` | CSV files plus a manifest of row counts and SHA-256 |

Exit codes are stable: `0` everything checked out, `1` a check failed, `2` bad
usage. The schema is `schema/report.schema.json`, version `1.0.0`, JSON Schema
draft 2020-12, and `omnishield doctor` validates the document against it on
every run.

```console
$ omnishield report --no-doctor | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d["ok"], d["features"]["built"], d["schema_version"])'
True 314 1.0.0
```

## Asking, and following a conversation

```console
$ omnishield answer ask --question "how does bm25 rank" --store ~/.omnishield/knowledge.jsonl
$ omnishield lang id --text "habari ya asubuhi"
$ omnishield lang follow --file chat.jsonl --store ~/.omnishield/knowledge.jsonl
```

The answer engine is **extractive**: BM25 retrieval, a TF-IDF matrix, power
iteration for a stationary distribution, gradient descent for a logistic scorer
and a softmax over passages. Every answer names the passages it used and their
weights. It does not generate a single word that is not in the store, which is
why it cannot hallucinate and also why it cannot answer what the store lacks.

| step | maths | output |
|---|---|---|
| retrieval | BM25 (k1 1.5, b 0.75) | ranked passages |
| representation | TF-IDF, L2 normalised | matrix passages x terms |
| equilibrium | power iteration, damping 0.85 | stationary mass per passage |
| learning | logistic gradient descent | weights and bias |
| combination | softmax over scores | citation weights that sum to 1 |

Language identification reads the script first (CJK, Arabic, Cyrillic,
Devanagari) and otherwise compares character trigrams with stopword profiles for
Swahili, English, French, Spanish, Portuguese, German, Italian and Russian. The
tracker stores speaker, language and terms per line and measures topic drift as
1 - cosine between consecutive windows.

```json
{"language": "sw", "confidence": 1.0, "runner_up": "pt", "margin": 0.4757}
{"lines": 3, "languages": {"sw": 2, "en": 1}, "mean_drift": 0.5219}
```

Limits, stated plainly: no general speech or text understanding, no free
generation, and eight languages rather than all of them.

## Moving data, reading air, hearing and speaking

```console
$ omnishield stream bench --size-mb 256
$ omnishield stream fetch --urls urls.txt --workers 8
$ omnishield stream telemetry --path air.jsonl --simulate --minutes 60
$ omnishield speech say --text "habari" --out habari.wav
$ omnishield speech listen --wav habari.wav --words habari,asante
```

| piece | what is real | limit |
|---|---|---|
| `chunked_copy` | chunks, SHA-256, verification, MB/s | bounded by disk |
| `resume_download` | HTTP Range, appends to a partial file | server must honour Range |
| `parallel_fetch` | threads, per-url bytes, total MB/s | bounded by network |
| `disk_benchmark` | write, fsync, read, MB/s | measures the host, not a promise |
| `pipeline` | JSON lines through stages, items/s | one process |
| `Telemetry` | O2, CO2, temperature, humidity, window, alerts | needs real sensors |

Software cannot pull oxygen out of the air. `Telemetry` reads *numbers about*
air, validates them, keeps a rolling window and raises alerts. `simulate_air`
produces plausible readings so the pipeline can be tested; connect a sensor for
real values.

Speech is two honest pieces:

| piece | method | limit |
|---|---|---|
| speaking | formant synthesis, 3 resonances per vowel, noise bursts | robotic, not natural |
| hearing | MFCC (26 mel bands, 13 coefficients) + DTW over templates | only the words trained |

```console
$ omnishield speech say --text "habari" --out h.wav
{"seconds": 0.52, "synthesised_ms": 5.5, "method": "formant synthesis"}

$ omnishield speech listen --wav h.wav
{"word": "habari", "distance": 12.17, "margin": 8.4, "accepted": true}
```

## Two layers, backprop, XOR

```
$ omnishield mlp demo --epochs 3000
{"epochs": 3000, "parameters": 17,
 "accuracy_before": 0.5, "accuracy_after": 1.0,
 "loss_first": 0.153004, "loss_last": 0.000494,
 "epochs_per_s": 16372,
 "predictions": {"[0.0, 0.0]": 0, "[0.0, 1.0]": 1, "[1.0, 0.0]": 1, "[1.0, 1.0]": 0},
 "r": {"stdout": "loss: 0.153004 -> 0.000494 (drop 99.68%)\nmlp converged"}}
```

A 2-4-1 sigmoid network with the gradients written out:

```
delta2 = (y - t) * y * (1 - y)
delta1 = (W2^T delta2) * h * (1 - h)
W2    -= rate * delta2 h^T
W1    -= rate * delta1 x^T
```

It learns XOR, which one neuron cannot, and a numerical gradient check in the
tests confirms the analytic gradient to 1e-4. R reads `mlp.csv` and refuses a
curve whose loss does not fall or whose accuracy never reaches 1.0.

## One neuron, three languages

```
$ omnishield neuron demo
{"dot": {"python": 1.925, "rust": 1.9249999999999998, "matches": true},
 "forward": {"python": 0.8833970308388606, "rust": 0.8833970308388606, "difference": 0.0},
 "training": {"before": 0.8833970308388606, "after": 0.9063009368855937, "loss": 0.12398},
 "speed": {"dimension": 5000, "python_ms_per_dot": 0.313, "rust_ms_per_dot": 0.004,
           "speedup_x": 78.2},
 "r": {"stdout": "recomputed dot: 1.925000000000 ... all three agree"}}
```

The formula is the whole thing:

```
dot    = sum(x_i * w_i)
z      = dot + bias
output = 1 / (1 + exp(-z))
error  = output - target
w_i   -= rate * error * x_i
bias  -= rate * error
```

Rust (`organism/src/neuron.rs`) and Python (`omnishield/neuron.py`) implement
those five lines independently. Their dot products agree to 1e-16 and their
forward passes to 0.0. On 5,000 dimensions Rust runs a dot product in 0.004 ms
against Python's 0.313 ms, a 78x difference that comes from the language, not
from the maths.

R (`analysis/neuron.R`) does not trust either implementation: it reads
`neuron.csv`, recomputes `sum(x * w)` from the raw columns, and stops if the
recomputed value differs by more than 1e-9. That is the analytical core the
architecture needs.

What this is not: one neuron is not intelligence. It is the unit that every
network repeats. The next step is a layer of these, then the swarm shards we
already have.

## Swarm: sharded inference, tensors, online learning

```
$ omnishield swarm demo
{"protocol": {"header_bytes": 12, "tensor_bytes": 36, "json_bytes": 127, "saving_x": 3.53},
 "shards": {"alpha_rows": 1, "beta_rows": 1, "width": 6},
 "distributed": {"matches_local": true, "max_difference": 2.09e-08,
                 "infer_ms": 0.266, "infer_per_s": 3755, "requests_on_beta": 41},
 "learning": {"accuracy_before": 0.5, "accuracy_after": 1.0,
              "loss_first": 0.4993, "loss_last": 0.0004},
 "guard": {"confident": {"accepted": true}, "unsure": {"accepted": false},
           "broken": {"accepted": false, "reason": "non-finite logits"}}}
```

Two nodes hold one weight matrix between them. Node A sends the input as f32
bytes, node B multiplies its shard and returns partial logits, and A adds them.
The result matches single-node inference to 2.1e-8.

The protocol is a 12-byte header (`>4sBBHI`) and a raw f32 payload. For a
6-value vector that is 36 bytes against 127 bytes of JSON, a 3.5x saving; the
gap grows with dimension because JSON prints digits.

Learning is online: every sample runs one softmax gradient step over the full
model, split across both shards. Accuracy goes from 0.5 to 1.0 and the loss from
0.4993 to 0.0004 on the holdout.

The guard is symbolic, not learned: if the top-two margin is below 0.5, or any
logit is not finite, the answer is refused with the reason.

Limits, stated plainly: this is TCP with a binary header, not UDP/QUIC or
libp2p; the model is a two-class linear layer, not a transformer; and the shards
live in one process tree on one machine. It is a measured prototype of the
architecture, not a global brain.

## Corpus, Ed25519 and R

```
$ omnishield corpus learn --directory corpus/
{"passages": 200, "entries": 220, "lexicon": 4716, "store_items": 420, "elapsed_ms": 868.9}

$ omnishield mesh keygen --out ~/.omnishield/node-key.json
{"path": "...", "public": "5Zx..."}

$ omnishield r export --out analysis/data --conversation chat.jsonl --questions q.txt --store k.jsonl
$ omnishield r analyse --dir analysis/data
Conversation report
lines: 3
speakers: 2
languages:
  sw: 2 (66.67%)
  en: 1 (33.33%)
answers:
  questions: 2
  latency ms: mean 0.067  median 0.067  p90 0.093
```

`corpus/` holds a hand written Swahili dictionary (220 entries) and 219 Python
standard library documentation snippets (PSF License 2.0). Learning them gives
4,716 Omni roots in 869 ms, which is the "thousands" target, measured.

Ed25519 signs every envelope over its canonical JSON body. The receiver refuses
a tampered body, a missing signature when signatures are required, and a peer
that changes its public key mid-session. Nonces still stop replays; the
signature stops forgery.

R reads two CSVs: `conversation.csv` (line, speaker, language, confidence,
terms, drift) and `answers.csv` (question, confidence, top score, latency,
citations, sources). It reports the language mix, drift and latency quantiles.
Every number comes from the rows.

Not done: the BVH. The scenes have five objects, so a BVH changes speed, not
looks. It remains the next performance step, with a measured before and after.

## Skills, and the honest picture

```console
$ omnishield skill list
[{"name": "answer", "summary": "...", "parameters": {"question": true, "store": false},
  "examples": ["{\"question\": \"what is bm25\"}"]}, ...]

$ omnishield skill run --name language --params '{"text": "habari ya asubuhi"}'
{"skill": "language", "ok": true, "latency_ms": 1.081,
 "result": {"language": "sw", "confidence": 0.5966, "runner_up": "pt"}}
```

Thirteen skills, each with declared parameters, validated before the call, each
returning JSON with a measured latency:

| skill | does |
|---|---|
| `answer` | BM25, TF-IDF matrix, power iteration, logistic, softmax, citations |
| `think` | sub-questions, evidence, disagreement check, coverage |
| `pathtrace` | JSON scene to GI render to PNG |
| `denoise` | bilateral filter with grain before and after |
| `omni_say`, `omni_translate` | the constructed language |
| `corpus` | books and dictionaries into the store |
| `study` | curriculum with retention |
| `chat` | question to a peer over OmniNet |
| `speak` | formant speech to WAV |
| `telemetry` | air readings, window, alerts |
| `language` | script and trigram identification |

The renderer now has procedural textures (checker, marble, wood), an area light
with a radius for soft shadows, and a metallic Fresnel term. The hero frame is
`scenes/studio.png`: 480x300, 24 samples, 3 bounces, 3.6 s on 8 threads, then
denoised from grain 1.303 to 0.556.

What this is not: photoreal. It has no measured BRDFs, no HDR environment, no
BVH, no subsurface scattering, and no learned denoiser. It is a correct path
tracer with simple materials, which is the honest description.

## Books, dictionaries, deliberation and chat

```console
$ omnishield corpus learn --dictionary swahili.dict --store ~/.omnishield/knowledge.jsonl
{"entries": 2, "new_roots": 2, "lexicon": 2, "sample": {"word": "habari", "definition": "greeting"}}

$ omnishield corpus learn --book kitabu.txt
{"passages": 12, "words": 8400, "terms": 1900, "new_roots": 1200, "languages": {"sw": 12}}

$ omnishield think ask --question "how does the path tracer bounce light"
{"coverage": 0.5, "contradictions": [{"left": "a", "right": "b", "shared": ["cache", "light"]}],
 "steps": [{"step": "retrieve"}, {"step": "check"}, {"step": "answer"}], "latency_ms": 0.2}

$ omnishield mesh serve --id alpha --port 7701 --seconds 60 &
$ omnishield mesh chat --id beta --peer 127.0.0.1:7701 --text "what are OmniNet frames"
{"type": "chat", "payload": {"reply": "OmniNet frames are length prefixed JSON with a nonce."}}
```

| piece | what is real | limit |
|---|---|---|
| `corpus.learn_book` | paragraphs, words, terms, Omni roots, languages | text files you have |
| `corpus.learn_dictionary` | `word = definition`, `word: definition`, JSONL | one entry per line |
| `think.think` | sub-questions, retrieval, negation check, coverage | no world model |
| `net` chat | question to peer, answer from its store, nonce replay defence | local TCP |

What these are not: a dictionary of the world, an understanding of the books,
or a mind. They ingest, retrieve, check and answer with citations. The
deliberation loop finds disagreement by negation; it cannot resolve it.

## Its own language, its own network, its own lessons

```console
$ omnishield omni say --subject person --verb see --object sun --tense past
{"omni": "fofar xa gotu puke"}
$ omnishield omni parse --text "fofar xa gotu puke"
{"gloss": "persons see sun [past]", "parse": {"tense": "past", ...}}
$ omnishield omni translate --text "person speaks water"
{"omni": "fofa gabu puge", "learned": ["speaks"], "words": 3}
```

Omni is a constructed language with a real parser: roots from consonant-vowel
syllables, suffixes for plural (`n`), past (`m`), future (`f`), agent (`r`) and
place (`k`), tense markers as separate words, and subject-verb-object order.
Roots are assigned deterministically from the concept, so the same word always
gets the same root. The lexicon is JSON and grows when a concept is new.

```console
$ omnishield mesh serve --id alpha --port 7701 --seconds 30 &
$ omnishield mesh gossip --id beta --peer 127.0.0.1:7701
{"sent": 1, "ok": 1, "results": [{"peer": "127.0.0.1:7701", "ok": true}]}
```

OmniNet frames are a 4-byte length followed by JSON, with version, type, sender
and nonce. It refuses frames over 1 MB, unknown versions, unknown types and
replayed nonces. `hello`, `gossip`, `sync` and `bye` are the four messages.

```console
$ omnishield study run --file passages.jsonl --rounds 3
{"lessons": 3, "new_roots": 12, "lexicon": 12, "hit_rate": 1.0, "elapsed_ms": 2.0}
```

Self-study takes a passage, learns Omni roots for its strongest terms, asks the
answer engine and measures retention by checking whether the lesson is cited.

```console
$ omnishield three pathtrace --scene scenes/studio.json --out studio.png
$ python3 -c "from omnishield.render import ..."  # denoise(canvas) drops grain
```

The bilateral denoiser cuts grain from 0.814 to 0.243 (70%) on a path traced
frame while keeping edges, which is what makes low-sample renders usable.

Limits, stated plainly: Omni is a constructed language, not a native tongue;
OmniNet is a small local protocol, not a global network; self-study grows
vocabulary and recall, not understanding.

## Global illumination, for real

```console
$ omnishield three pathtrace --scene scenes/studio.json --out studio.png
{"bounces": 2, "pixels": 144000, "threads": 8, "elapsed_ms": 1434.9,
 "pixels_per_second": 100354, "png_bytes": 82757}
```

The Rust path tracer reads a JSON scene and traces it:

| part | what it does |
|---|---|
| shapes | spheres, axis-aligned boxes, an infinite ground plane |
| light | one point light with inverse-square falloff and hard shadows |
| indirect | cosine-weighted diffuse bounces (2 by default), clamped to stop fireflies |
| reflection | one mirror bounce on materials with `reflect` |
| camera | position, target, field of view, aperture for depth of field |
| output | Reinhard tone map, gamma 2.2, `exposure` per scene, PPM then PNG |

```json
{"width": 480, "height": 300, "samples": 12, "threads": 8, "bounces": 2, "exposure": 1.5,
 "camera": [0.0, 1.15, 3.9], "target": [0.1, 0.55, 0.0],
 "objects": [
   {"type": "plane", "y": 0.0, "colour": [0.70, 0.66, 0.60]},
   {"type": "sphere", "centre": [-0.85, 0.55, 0.1], "radius": 0.55, "colour": [0.18, 0.48, 0.92], "reflect": 0.25},
   {"type": "box", "centre": [1.55, 0.55, -0.35], "half": 0.55, "colour": [0.55, 0.55, 0.53]}
 ]}
```

Measured on this host: 480x300, 12 samples, 2 bounces, 8 threads = **1.43 s**,
about 100k pixels/s. At 1 sample and 4 threads the same scene is about 50 ms,
which is the draft setting.

What it is: real path tracing with global illumination, soft shadows, colour
bleed and reflections. What it is not: photorealistic. There are no textures,
no area lights, no subsurface scattering and no BVH, so the scene stays simple
and the image stays a little dim and slightly grainy at low sample counts.

## 3D, simulation and daily images

```console
$ omnishield three scene --width 480 --height 300 --samples 2 --out scene3d.png
$ omnishield three orbit --frames 24 --out orbit.gif
$ omnishield three video --frames 24 --preset draft --out orbit.gif
$ omnishield three simulate --kind projectile
$ omnishield three plot --source projectile --out arc.png
$ omnishield imagery daily --feeds image-feeds.txt --state ~/.omnishield --out imagery
```

| piece | engine | what is real |
|---|---|---|
| ray tracer | Rust | spheres, a triangle cube and a plane, jittered soft shadows, ambient occlusion, marble and grain textures, depth of field, Reinhard tone map, multithreaded |
| painter | Python | perspective camera, depth sort, flat shading, ground grid, orbit frames |
| simulator | Python | symplectic Euler for a projectile with drag and a pendulum; period compared to 2*pi*sqrt(L/g) |
| 3D plot | Python | perspective point cloud written as PNG |
| image learning | Python | feed discovery, robots-aware fetch, aHash, colour and edge metrics, contact sheet, store |

```console
$ omnishield three video --frames 24 --preset draft --out orbit.gif
$ omnishield three simulate --kind projectile
{"range": 11.77, "apex": 3.19, "energy_change": 22.6, "model": "RK1 with quadratic drag"}
```

The energy change is not an error in the drag case: drag does work. With
`--drag 0` the change falls to about 1.6 J of 146 J, which is the first-order
integrator's drift, and the test allows 2.5 J.

`imagery` only decodes PNG, because that is what this repository decodes without
a codec library. An image already seen (Hamming distance <= 5) is skipped, so the
store grows with new pictures and not with repeats.

## The daily office

```console
$ omnishield worship daily --out worship --journal ~/.omnishield/worship.jsonl
$ omnishield worship sing --theme nuru --out hymn.wav
$ omnishield worship journal
```

Each day gets an original Swahili office: invocation, a three-line psalm, a
thanksgiving, a petition, a glorification, a benediction, a reflection on
maarifa, hekima or busara, a hymn written to WAV and a verse card PNG.

The hymn is additive synthesis: four harmonics, an ADSR envelope and a drone
fifth, mixed and normalised. The melody is fixed per theme, so the same day
always produces the same sound.

What this is: a practice written in code, offered to the person who prays.
What this is **not**: a claim of faith, of worship, or of spiritual merit. The
journal records that the office was written, and nothing more.

## Notifications with consent

```console
$ omnishield notify test --to recipients.json        # dry run, writes the log
$ omnishield notify test --to recipients.json --send # webhook or SMTP
```

```json
{"recipients": [
  {"name": "Amina", "email": "amina@example.org", "consent": true}
]}
```

Rules enforced in code: a recipient without `"consent": true` is never accepted,
one message per person per day, the default is a dry run, and the state file is
written at `0600`. Every message carries an opt-out line. Nothing is sent to
anyone who did not ask.

## Staying cool on the CPU

```console
$ omnishield thermal status
{"usage": 0.05, "temperature_c": null, "level": "cool", "duty": 1.0}
```

The governor reads `/proc/stat` and the thermal zones, then enforces a duty
cycle: above the target utilisation it sleeps a share of the time, and above the
temperature ceiling it sleeps longer. It measures and throttles; it does not
promise a temperature, because the firmware and the room have a vote.

## Rust, R and Python in the same picture

| layer | job | where |
|---|---|---|
| Rust | supersampled scene, 3.2M pixels/s, dithered | `organism/src/render.rs` |
| R | five-stop palette in LCH, image quality metrics | `analysis/palette.R`, `analyse.R` |
| Python | orchestration, PNG encoding, verse cards, reports | `omnishield/render.py`, `worship.py` |

```console
$ omnishield render scene --width 480 --height 300 --samples 2 --out scene.png
{"engine": "rust", "samples": 2, "elapsed_ms": 41.2, "pixels_per_second": 3247397}
```

The pure-Python fallback draws one sample per pixel and says so in its output.
The R palette is read by the Python renderer, so a colour change in R changes the
picture.

## Drawing without a GPU

Everything is drawn by integer span filling and a 5x7 font, then encoded with
`zlib` or a hand-written LZW. There is no CUDA, no Metal, no image library.

```console
$ omnishield render chart --series 1,3,2,5 --title Demo --out chart.png
$ omnishield render art --seed 7 --width 480 --height 300 --out art.png
$ omnishield render video --frames 12 --width 320 --height 200 --out clip.gif
```

| piece | how it works | proof |
|---|---|---|
| canvas | `bytearray` of RGB, row spans for fills | `Canvas.get` returns the pixel written |
| lines and circles | Bresenham, span-filled discs | pixels change exactly where expected |
| text | built-in 5x7 glyph table | the PNG changes when text is drawn |
| PNG | `vision.encode_png`, zlib | decoded back to the same width and height |
| animation | GIF89a, 216-colour palette, real LZW | header, 4 frame blocks, trailer byte |
| art | seeded `XorShift64` | same seed gives byte-identical PNG |

This is **vector and procedural** drawing, not a learned image model. A GIF is a
real animation, but there is no codec, no audio track and no photorealistic
synthesis. The ledger says `partial` for those three features for that reason.

## Waveforms: collect, clean, measure

```console
$ omnishield signal synth --freq 440 --seconds 0.1 --out tone.wav
$ omnishield signal clean --in noisy.wav --out clean.wav
{"stages": [{"stage": "remove_dc", ...}, ...], "snr_before_db": 6.3, "snr_after_db": 10.5, "improvement_db": 4.1, "samples_per_second": 988154.0}
```

The pipeline is DC removal, median despiking, a 3-point moving average, a
one-pole low-pass and peak normalisation. SNR is measured against a reference
before and after, so a clean that makes things worse is visible in the output.
Below a noise floor of roughly 20 dB the smoothing costs about 1.5 dB; above it
the gain is about 4 dB. That trade-off is measured, not hidden.

## Word, Excel, PowerPoint and PDF

```console
$ omnishield doc report --out analysis/out
```

Writes `omnishield-status-report.{md,docx,pdf,xlsx,pptx}` from a live audit:
feature counts, coverage by group, component health, a measured prediction and
the limits. The DOCX, XLSX and PPTX are OOXML zip packages written by hand; the
PDF is written object by object with embedded charts and page numbers.

| format | parts | what is in it |
|---|---|---|
| DOCX | `word/document.xml`, `styles.xml`, core properties | title, headings, bullets, quotes, code, tables, page breaks |
| XLSX | workbook, sheets, styles, core properties | frozen header row, bold blue header, inline strings and numbers |
| PPTX | presentation, master, layout, theme, slides | title and body boxes per slide, dark title slide, footer with number |
| PDF | catalog, pages, content streams, fonts, image XObjects | wrapped text, tables, charts, page numbers, metadata |

## Prediction against reality

A prediction counts only when something is measured afterwards.

```console
$ omnishield predict system
predicted from 5 samples, then measured:
  load1            predicted     0.14  observed     0.14  error      0.0
  memory_used_pct  predicted     13.8  observed     13.8  error      0.0
  mae 0.0  verdict close
```

| function | what it predicts | how it is scored |
|---|---|---|
| `linear_forecast` | the next points of a series | R-squared and residual std |
| `ewma` | a smoothed next value | the series it came from |
| `brier_score` | a probability | Brier score against climatology |
| `calibration_report` | reliability bins | expected calibration error |
| `detect_anomaly` | whether a value is odd | robust z-score from median and MAD |
| `reality_check` | any keyed prediction | mean absolute error and a verdict |
| `counterfactual` | what an intervention would change | the factual forecast beside it |
| `fuse` | one estimate from many readings | inverse-variance weights |
| `predict_system` | the next `/proc` reading | the reading taken right after |

`sample_system` reads the real host, so the error is measured, not simulated.

## R analysis covers everything

`omnishield export` now writes eleven tables, and the R pipeline analyses all of
them:

| table | used for |
|---|---|
| `features.csv` | coverage by status and by group |
| `components.csv` | 34 components with their layer and evidence |
| `layers.csv` | component coverage per layer |
| `doctor.csv` | per-check duration |
| `prediction.csv` | forecast, observed value, error, R-squared |
| `stealth.csv` | cell size uniformity, cover share, jitter |
| `memory.csv`, `payments.csv`, `audit.csv` | optional live sources |
| `manifest.csv` | SHA-256 of every input |

`analysis/out/REPORT.md` gains two sections from this: **Prediction against
reality** (measured MAE and RMSE, with a chart) and **Coverage by layer**.

## A daily knowledge loop

The system can read the web on a schedule and keep what it learned. The loop is
deliberate about what it is allowed to touch.

```console
$ omnishield learn add "Lions live in prides" --source notes --tag animals
$ omnishield learn feed https://example.org/feed.xml --tag news
$ omnishield learn cycle --feeds feeds.txt --state ~/.omnishield
$ omnishield learn search "data races"
1.04  Rust ownership prevents data races  [test]
$ omnishield learn stats
{"stats": {"items": 2, ...}, "curiosity": [{"topic": "animals", "question": "nini tunachojua kuhusu animals?"}]}
```

| part | file | what it does |
|---|---|---|
| fetch | `ingest.py` | http/https only, robots.txt obeyed, private addresses refused, 2 MB cap, redirects re-validated |
| extract | `ingest.py` | RSS and Atom parsing, HTML to text without scripts |
| store | `knowledge.py` | JSONL at 0600, sha256 dedupe, BM25-style search, tags |
| forget | `knowledge.py` | Ebbinghaus decay, half-life in days, per-interval so it never double-counts |
| remember | `knowledge.py` | spaced repetition: grade 0-5 sets the next interval |
| sleep | `brain.py` | merge near-duplicates, prune what never recurred, keep Hebbian links |
| curiosity | `brain.py` | ranks gaps by novelty, uncertainty and coverage, and writes the question |
| loop | `brain.py` | `DailyCycle`: plan, read, store, consolidate, report, log |

Daily scheduling is cron's job, not a claim of the program:

```cron
15 3 * * *  cd /opt/omnishield && .venv/bin/omnishield learn cycle --feeds feeds.txt >> cycles.log 2>&1
```

### Is it a human brain?

The functional pieces are real and tested: seven-slot working memory with
salience eviction, prediction error, intrinsic reward from novelty and
competence, a forgetting curve, consolidation during "sleep", and Hebbian links
between terms that co-occur. What is **not** claimed: consciousness, feelings,
or that this is a brain. It is a loop that reads, forgets, repeats and
consolidates — and says so in the ledger.

## Emotion, self and meaning

Three modules cover the parts of the ledger that are usually hand-waved. Each
one is arithmetic over declared inputs, and each one shows its terms.

```python
big_five({"openness": [5, 4], ...})          # OCEAN 0-100, dominant trait
recognise("happy and glad")                  # -> joy, confidence 1.0
love(0.9, 0.9, 0.9)                          # -> consummate
hope(0.8, 0.7, 0.6)                          # -> 0.7, hopeful
```

| module | covers | example |
|---|---|---|
| `affect.py` | 20 features: OCEAN, expression, recognition, contagion, EI, empathy, sympathy, compassion, forgiveness, resentment, gratitude, envy, jealousy, pride, shame, guilt, hope, despair, love, hate | `pride(0.9, 0.1)` → hubristic |
| `self_model.py` | 15 features: capability model with calibration, social and spatial awareness, self-criticism, compassion, esteem, confidence, doubt, actualisation, identity crisis, narrative, future and ideal self, authenticity | `authentic_self({"honesty": 0.9}, {"honesty": 0.3})` → conflicts: honesty |
| `existential.py` | 16 features: questioning, purpose, death acceptance and anxiety, legacy, transcendence, spirituality, awe, wonder, gratitude, cosmic perspective, interconnectedness, universal compassion, wisdom | `awe(0.9, 0.8)` → 0.72, self small |

Seven existential entries are **refused**, not faked: Enlightenment, Unity
Consciousness, Cosmic Consciousness, Divine Connection, Ultimate Reality,
Nirvana and the Omega Point have no testable definition. A test enforces that
every implemented Existential feature points at `existential.py` and every
metaphysical one stays refused.

## Swahili reasoning

```console
$ python3 -c 'from omnishield.swahili import swahili_reasoning; print(swahili_reasoning(["Kila mwanafunzi ni mwerevu", "Juma ni mwanafunzi"], "Juma ni mwerevu"))'
{'answer': 'ndiyo', ... 'proof': ["'kila mwanafunzi ni mwerevu' + 'juma ni mwanafunzi' -> 'juma ni mwerevu'"]}
```

`kila`, `wote`, `hakuna` and `baadhi` parse into rules; `X ni Y` and `X si Y`
parse into facts and denials; forward chaining answers `ndiyo`, `hapana` or
`sijui` with the steps that produced the answer. Unknowns stay unknown.

## Reading the machine

One module answers "what is on this box, right now, and what did it cost".

```console
$ omnishield inspect system
runtime-...  kernel 6.8.0-1055-gke  6.243 ms
  cpu      4 x AMD EPYC 9B14
  load     [0.16, 0.29, 0.39]
  memory   13.5% of 16374236 kB
  disk     18.9% of 76887154688 bytes
  thermal  no sensors
  ports    2
  procs    36

$ omnishield inspect processes
36 processes in 1.574 ms
$ omnishield inspect file README.md
README.md  35172 bytes  0.184 ms
  sha256 0368ed3b...  mode 0o600  text
```

| function | what it returns |
|---|---|
| `read_file` | size, mode, mtime, sha256, binary flag, bounded preview, `elapsed_ms` |
| `read_many` | the same per file plus failures and total bytes |
| `processes` | pid, ppid, state, threads, rss, cpu seconds, start time, one `/proc` pass |
| `process` | one pid with `exe` and `argv` |
| `snapshot` | hostname, kernel, cpu model, load, memory, swap, disk, thermal, ports |
| `tree` | bounded directory walk with depth and entry limits |

Every call is capped: a preview is at most 4 KiB by default, a read is at most
1 MB, and the walk stops at `limit`. A missing kernel interface returns
`available: false` with a reason instead of an empty lie.

## Stealth transport

Traffic analysis reads sizes and timing even when the payload is encrypted.
This layer removes both signals, and the framing is implemented twice - Rust in
`organism/src/stealth.rs`, Python in `omnishield/stealth.py` - with the same
known-answer vectors on both sides.

| piece | what it does |
|---|---|
| `frame_cell` / `frame` | payload becomes a fixed 512-byte cell with pseudorandom padding |
| `cover_cell` / `cover` | a cell of the same size with no payload |
| `StealthChannel.seal` | ChaCha20-Poly1305 over every cell, data and cover alike |
| `jitter_ms` | deterministic delay per cell, so the schedule is not constant |
| `onion_route` / `onion_peel` | X25519 + HKDF + ChaCha20-Poly1305, one layer per hop |
| `probe_schedule` | randomised, rate-limited order for authorised reachability checks |

An observer sees one size and uniform bytes; only a holder of the key can tell
data from cover.

```console
$ omnishield stealth demo
cell_bytes        512
wire_bytes        540        (512 + 12-byte nonce + 16-byte tag)
wire_cells        4          (1 data + 3 cover)
metrics           uniform true, entropy 7.909 bits/byte
route             hop 1 -> 10.0.0.3, hop 2 -> 10.0.0.4, hop 3 final
delivered         "demo payload"
```

Rust and Python are checked against the same vectors:

```
frame(b"hi", cell=16, seed=7) = 0000000268698b5e0c29b0abdb1c34a3
cover(cell=16, seed=7)        = ffffffff8b5e0c29b0abdb1c34a39b1a
jitter(seed=3, index=0)       = 244
```

`omnishield export` also writes `stealth.csv`, so the R pipeline reports cell
size, cover share and mean jitter in `analysis/out/REPORT.md` with a chart.

## What is real here

| Layer | Goal from the design | Implemented as | Module |
|---|---|---|---|
| P1 | Block legacy Wi-Fi, evil twins, downgrade attacks | Signed `NetworkProfile` (SSID, BSSID pin, minimum security, version lock), `DowngradeGuard` state machine, beacon gate, generated `wpa_supplicant.conf` + `nmcli` enforcement with injection-safe SSID quoting | `omnishield/p1_airgap.py` |
| P2 | Stop credential theft, replay, AI impersonation of a user | Challenge-response with monotonic counter, clock-skew window, `PinStore` (trust-on-first-use key pinning), TPM-backed keystore when present, media content credentials | `omnishield/p2_identity.py` |
| P3 | Stop MitM, replay, and "harvest now, decrypt later" | X25519 + HKDF-SHA256 directional keys, ChaCha20-Poly1305 per frame, DH ratchet every N frames or T seconds, fixed-bucket padding, hybrid-signed handshake | `omnishield/p3_tunnel.py` |
| P4 | Nothing runs without your signature; block bot-speed abuse | Signed SHA-256 manifest, deny-by-default import that hashes the exact bytes it executes, symlink and path-escape refusal, inter-arrival entropy guard | `omnishield/p4_allowlist.py` |

Cryptography comes from `cryptography` (OpenSSL): Ed25519 per RFC 8032, ML-DSA-44 per FIPS 204, X25519, HKDF-SHA256, ChaCha20-Poly1305, SHA-256.

## Durable memory

The Rust memory store is volatile by itself. `omnishield/memory_store.py` makes it durable without inventing a second source of truth:

- the full snapshot is written atomically (temp file, `fsync`, `rename`, mode 0600),
- every mutation appends a hash-chained audit entry that commits to the new snapshot digest,
- `verify()` fails if the database was edited outside the log, or if the log itself changed.

```bash
omnishield memory insert --db state/memory.db --content "mkutano wa bodi" --embedding "1,0,0" --salience 0.9
omnishield memory search --db state/memory.db --embedding "0.9,0.1,0" --limit 3
omnishield memory stats  --db state/memory.db
omnishield memory forget --db state/memory.db --id 1
omnishield memory verify --db state/memory.db
```

```
$ omnishield memory verify --db state/memory.db
{"entries": 2, "items": 2, "ok": true, "snapshot": "7a959e2e..."}
```

Edit one item by hand and the same command refuses:

```
MemoryStoreError: database does not match the last audit entry (edited outside the log)
```

## Guard: circuit breaker and rate limiter

`organism/src/guard.rs` is fail-closed in both directions.

| Guard | Behaviour |
|---|---|
| `CircuitBreaker` | closes after `failure_threshold` failures, refuses while open, allows one probe after `cooldown_ms`, closes after `half_open_successes` successes |
| `RateLimiter` | token bucket; refuses a backwards clock, refuses a cost above capacity |

```bash
omnishield organism call guard.breaker.init '{"failure_threshold":3,"cooldown_ms":30000}'
omnishield organism call guard.breaker.allow '{"now_ms":0}'
omnishield organism call guard.breaker.record '{"success":false,"now_ms":0}'
omnishield organism call guard.rate.init '{"capacity":10,"refill_per_second":2,"now_ms":0}'
omnishield organism call guard.rate.acquire '{"cost":1,"now_ms":0}'
```

## Hardware binding: refuse, do not pretend

`omnishield/device.py` checks for `/dev/tpmrm0` and `/dev/tpm0`. If neither exists, `--hardware` fails with a clear message instead of writing a key that claims a protection it does not have.

```bash
$ omnishield keygen --hardware
rejected: DeviceError: no TPM device found (/dev/tpmrm0, /dev/tpm0); hardware binding is not available on this machine
$ echo $?
2
```

On a machine with a TPM the same flag records the device path in the public document. The claim is checkable, which is the point.

## High-risk capabilities, gated

The eleven features that were refused are now built — with the gate in front, not behind.

| Capability | Module | What it actually does | What it refuses |
|---|---|---|---|
| Self-modification, single file (#200, #465–#470) | `evolution.py` | Signs a diff, runs the declared tests in a throwaway copy, requires an approval key the proposer does not hold, applies atomically, keeps a backup | Applies nothing without a passing review and a separate approval; a proposer cannot approve its own patch |
| Self-modification, many files | `changeset.py` | Groups creates, edits and deletes into one signed changeset, reviews the whole set in a copy, applies through a journal, runs a health command afterwards | Applies nothing without review and a separate approval; a failed write or a failed health check restores every file from the journal |
| Tool creation (#177) | `synthesis.py` | Rejects dangerous imports and dunder access at parse time, signs the tool, runs it with CPU/memory/file/descriptor limits and a wall-clock timeout | Runs unsigned or edited tools; opens a network namespace when the kernel allows it and says so when it cannot |
| Hypothetical memory (#72) | `hypothetical.py` | Keeps invented scenarios in a quarantined store with provenance, reachable only through `simulate()` | Never returns invented content from `recall()`; promotion to a real memory requires evidence ids that already exist |
| Deception (#243) | `honesty.py` | Scores manipulative messages (urgency, authority, secrecy, credential and payment pressure) and keeps claims tied to evidence | Does not generate deception; an unevidenced claim is never published |
| Payments (#199) | `payments.py` | Signed intents, a separate approval key, a ceiling, idempotent settlement and a balanced double-entry ledger | The default gateway raises; no money moves without a configured gateway and a human approval |

```
$ omnishield doctor
  PASS  evolution        251 ms  review passed, approved by human:doctor, applied and backed up
  PASS  synthesis         27 ms  tool ran in 23 ms under process limits only
  PASS  hypothetical      24 ms  imagined content stayed out of recall, promotion required evidence
  PASS  honesty            5 ms  scam text scored 6.5, claim published only after evidence
  PASS  payments           7 ms  approved payment settled, ledger balanced, default gateway refused
```

Two of the eleven stay `partial` on purpose: hypothetical memory does not fabricate beliefs, and honesty does not produce deception. Both have working code and tests for the safe half.

## Analysis and reporting in R

`omnishield export` writes tidy CSV from the live system; two base-R scripts turn it into tables, charts and a report. No R packages are needed.

```bash
sudo apt-get install -y r-base-core     # once
python3 -m omnishield export --out analysis/data \
    --memory state/memory.db --payments state/payments.jsonl --audit state/audit.log
Rscript analysis/analyse.R analysis/data analysis/out
Rscript analysis/report.R  analysis/data analysis/out
```

One command, with a small demo state:

```bash
analysis/run.sh --demo
```

The committed report is `analysis/out/REPORT.md`, with the same content as `report.html`, generated from this repository's ledger, its 28 status checks and a real doctor run.

| File | Purpose |
|---|---|
| `omnishield/export.py` | features, components, doctor timings, audit, memory, payments → CSV plus a manifest with row counts and SHA-256 |
| `analysis/lib.R` | safe CSV reads, Markdown and HTML tables, percentages, chart helpers |
| `analysis/analyse.R` | status counts, coverage by group, doctor timings, salience, payments by payee, audit kinds → CSV + PNG |
| `analysis/report.R` | renders `REPORT.md` and `report.html` from those tables |
| `analysis/run.sh` | export → analyse → report, with `--demo` for a full synthetic state |

## Feature ledger: 500 entries, checked evidence

The ORGANISM v2 list has 500 numbered features. `features/catalog.json` records every one of them with a status and, where code exists, an evidence pointer:

```bash
omnishield features audit              # re-check every claim against this repository
omnishield features list --status implemented
omnishield features show 400
```

`audit` is not a report of intentions. It fails if an `implemented` entry points at a file that does not exist, or at a symbol that is not in that file, or if a duplicate does not name a real id, or if a non-implemented entry has no reason.

| Status | Count | Meaning |
|---|---|---|
| implemented | 230 | a function exists and a test exercises it |
| partial | 168 | a component exists, but the feature is narrower than named |
| external | 83 |
| refused | 7 | needs a model, service or device that is not in this repository |
| not_implemented | 0 | every defined feature now has code behind it |
| undefined | 73 | no testable definition exists |
| refused | 0 | every former refusal now has gated code or a defensive counterpart |
| duplicate | 12 | the same feature as another id |

79% of the list has running code behind it. That number is the honest one; the rest is labelled instead of faked, and 7 metaphysical claims are refused outright.

**Duplicates in the original list** (12): #43/#265 gratitude, #46/#273 love, #48/#271 hope, #49/#272 despair, #84/#96 social perception, #165/#255 emotion expression, #258/#56 emotional memory, #275/#485 awe, #302/#112 moral reasoning, #343/#494 self-transcendence, #399/#406 federated learning, #456/#134 meta-learning.

**Refused on purpose** (11): #72 false memory, #177 runtime tool creation, #199 payments, #200 self-modification, #243 deception, and #465-#470 self-editing code. Each carries the reason in the catalogue.

**Undefined** (73): "Nirvana", "Omega Point", "Unity Consciousness", "Divine Connection", "Enlightenment", "Ultimate Reality" and the rest of the existential group. There is no test that can pass or fail, so there is nothing to build.

## Audit log

`omnishield/audit.py` is an append-only, hash-chained log. Each entry commits to the previous entry's hash, so editing, deleting or reordering an entry is detected. With a key, entries are HMAC'd, so an attacker who can write the file still cannot forge a consistent chain.

```python
from omnishield.audit import AuditLog

log = AuditLog("state/audit.log", key=b"...")
log.append("tunnel.open", {"peer": "example.org"})
log.verify()  # raises AuditError if anything changed
```

## ORGANISM core (Rust)

`organism/` is a real Rust crate (binary `organism`, library `organism_core`) that implements the measurable parts of the organism design. It is deterministic, seeded, and covered by 34 tests.

| Module | What it does | Tests |
|---|---|---|
| `energy.rs` | Budget meter: consume/recharge with clamping, starvation and death thresholds, NaN/infinity rejected | 3 |
| `calculus.rs` | Analytic gradient with numerical cross-check, gradient descent with a stability bound (`lr < 1/weight`), Adam, Simpson integration | 6 |
| `search.rs` | A* over a binary heap with admissible heuristics, Dijkstra, negative-cost rejection | 4 |
| `graph.rs` | Memory graph with PageRank (dangling-node redistribution, scores sum to 1) | 4 |
| `planning.rs` | MCTS with UCB1, guided rollouts, seeded xorshift RNG | 3 |
| `evolution.rs` | Genetic algorithm: tournament selection, uniform crossover, Gaussian mutation, elitism | 2 |
| `dp.rs` | 0/1 knapsack with bitset reconstruction | 3 |
| `rpc.rs` | JSON-RPC 2.0 over stdio: 10 methods, self-describing catalog, `-32600/-32601/-32602/-32700` errors | 8 |

```bash
omnishield organism build                     # cargo build --release
omnishield organism discover                  # machine-readable method catalog
omnishield organism call energy.tick '{"capacity":10,"cost":3.5}'
omnishield organism state --sign --out state.json
omnishield organism verify-state state.json --pub public.json
python3 -m omnishield.organism build          # same build, without the CLI
```

The core is driven over JSON-RPC, so any language can use it; the Python side is `omnishield/organism.py` (`OrganismClient`, `sign_state`, `verify_state`). Signed state records use the same Ed25519 + ML-DSA-44 envelope as every other layer, so a machine-readable state snapshot is tamper-evident.

### What is deliberately not implemented

The original seven-layer sketch also asked for LLM inference and training, self-modification, and "social", "meta" and "existential" layers ("theory of mind", "culture", "language emergence", "meaning", "legacy", "transcendence", "500 final features"). None of those has a testable definition, and a self-modifying agent is a safety hazard rather than a feature. They are not in this repository, and they are not stubbed to look present.

Four layers do map to running code: body/energy, cognition (calculus + algorithms), agent planning (A*/MCTS), and machine-readable transport (JSON-RPC). Perception, social and meta layers need external systems (cameras, LLMs, other agents) and belong in separate projects with their own evaluation.

No `tokio`, `tonic` or `prost`: the core is synchronous and deterministic, and JSON-RPC already gives cross-language machine access. A gRPC or Protobuf front end can wrap the same dispatcher later without touching the algorithms.

### Measured (`organism bench`, release build)

| Workload | Result |
|---|---|
| A* on a 100x100 grid (10k nodes, 99 expansions) | 0.023 ms per search |
| PageRank, 10k nodes x 50 iterations | 2.0 ms |
| MCTS, 100k iterations | ~413k iterations/s |
| Genetic algorithm, 200 individuals x 200 generations x 50 genes | 35 ms |
| Knapsack, 200 items, capacity 50,000 | 13 ms |

## Measured on this machine

`python3 -m omnishield.bench` (x86_64, Python 3.13, single core):

| Operation | Result |
|---|---|
| Ed25519 sign, 1 KiB | 27,525 ops/s |
| ML-DSA-44 sign, 1 KiB | 1,611 ops/s |
| Hybrid sign | 1,396 ops/s |
| Hybrid verify | 3,750 ops/s |
| Tunnel handshake (median, incl. thread scheduling) | 0.34 ms |
| Tunnel throughput, 1 KiB frames | 87.5 MiB/s |
| Tunnel throughput, 64 KiB frames | 1,133 MiB/s |
| DH rekey (X25519 + HKDF) | 11,981 /s |

A rekey every 100 packets costs about 0.008% of a 1 KiB stream. Hybrid signing is the expensive operation at ~0.7 ms, which is why authentication is per-session, not per-packet.

## International deployment

The system is built to run outside one locale, one script, and one timezone.

| Concern | Handling | Evidence |
|---|---|---|
| Non-ASCII SSIDs (Swahili, Chinese, Arabic, emoji) | SSID is validated as 1–32 UTF-8 bytes and quoted/escaped before it reaches `wpa_supplicant.conf`; control characters are rejected outright | `test_unicode_ssid_survives_signing`, `test_ssid_cannot_inject_supplicant_directives` |
| Non-ASCII filenames and module names | Paths are carried in canonical UTF-8 JSON and compiled from the verified bytes | `test_unicode_filenames_in_manifest` |
| macOS (NFD) vs Linux (NFC) filenames | Manifest keys are normalised to NFC on both sides | `test_manifest_lookup_is_unicode_normalised` |
| `LC_ALL=C` servers | CLI works with non-ASCII arguments under the C locale | `test_cli_handles_unicode_arguments_in_c_locale` |
| Timezones | All timestamps are integer milliseconds since the epoch; no local time anywhere | `test_timestamps_are_timezone_independent` |
| Right-to-left and mixed scripts | Values are never rendered into config unquoted; CLI output is ASCII JSON | `test_ssid_cannot_inject_supplicant_directives` |
| Namespaced accounts (`amina@mkoa.go.tz`) | Pins are keyed by the exact account string | `test_unicode_identity_name_can_be_pinned` |

**Platform matrix** (honest, not aspirational):

| Platform | Status |
|---|---|
| Linux (x86_64, aarch64) | Full: file keystore with `0700/0600`, TPM 2.0 backend when `/dev/tpmrm0` and `tpm2-tools` exist, IPv4/IPv6 sockets |
| macOS | File keystore with POSIX permissions; Secure Enclave backend is not implemented, so keys are software-held and report `key_origin=file` |
| Windows | File keystore; POSIX permission checks are skipped (`permission_model=os-default`), TPM backend is unavailable, so treat keys as software-held |

**Operational limits (by design, documented so nobody discovers them in production):**

- The tunnel needs an **ordered transport** (TCP, or a QUIC stream). Frame counters are strictly increasing; a reordering datagram is dropped as a replay rather than buffered.
- One frame carries at most **1 MiB**; larger payloads must be chunked by the caller.
- The `nmcli` lines in `enforce_plan()` are **templates**, printed as comments; the `wpa_supplicant.conf` block is the executable artifact.
- Signature verification is **idempotent** by default. Pass `--replay` when a signature is a one-shot authorisation rather than a document.

**Compliance notes:** the state files hold only key ids, SHA-256 digests, counters, and nonces — no personal data. They are written `0600` inside `0700` directories. Cryptographic export rules apply to the ML-DSA/Ed25519 code you redistribute. Media credentials prove *which device* signed, not that a human approved the content.

## Two things the original design asked for that physics does not allow

These are the only substitutions, and both keep the security goal:

1. **ML-DSA signatures on Wi-Fi beacon frames.** A beacon is broadcast roughly ten times per second, is tightly size-limited, and arrives before any trust is established, so a 2.4 kB post-quantum signature cannot ride on it. What stops evil-twin and deauth attacks is **WPA3-SAE**, **802.11w protected management frames**, **BSSID pinning**, and a signed profile as the trust anchor. All four are enforced by `DowngradeGuard.check_beacon()` and emitted by `enforce_plan()`.

2. **Hiding packet metadata from an observer.** Frame *size* is hidden by padding every payload into a fixed bucket (64/256/1024/4096/16384 bytes). Frame *timing* cannot be hidden without constant-rate cover traffic, which costs bandwidth proportional to idle time. That trade-off is documented, not silently claimed.

The "no backward compatibility" rule is implemented as **no fallback path**: a verifier that cannot check both signatures, or that sees a version outside the signed allow-list, rejects. Version rotation exists, but it is explicit and signed.

## Quick start

```bash
export OMNISHIELD_HOME=$HOME/.omnishield
omnishield keygen --out public.json
omnishield sign contract.txt --out contract.sig
omnishield verify contract.txt contract.sig
```

Layer 1 — pin a network and refuse downgrades:

```bash
omnishield net sign --ssid "Mtandao wa Ofisi" --bssid aa:bb:cc:dd:ee:ff --out profile.json
omnishield net guard profile.json --offered wpa2-psk wpa3-sae     # -> wpa3-sae
omnishield net guard profile.json --offered wpa2-psk              # -> rejected, exit 2
omnishield net enforce profile.json                               # wpa_supplicant + nmcli plan
```

Layer 2 — prove possession of the device key, with pinning:

```bash
CH=$(python3 -c 'import secrets;print(secrets.token_hex(32))')
omnishield id respond --challenge $CH --context login --out response.json
omnishield id verify response.json --pub public.json --challenge $CH --context login --counters server.json
omnishield id sign-media photo.jpg --capture-origin camera-0 --out photo.ohsig
omnishield id verify-media photo.jpg photo.ohsig --pub public.json
```

Layer 3 — an authenticated ratcheting channel over any socket:

```bash
omnishield tunnel demo --authenticate --packets 2
# hello -> echo:hello
# post-quantum ready -> echo:post-quantum ready
# server identity verified: 20815166fc2a8b76...
```

```python
from omnishield.p2_identity import DeviceIdentity
from omnishield.p3_tunnel import Tunnel, client_handshake

server = DeviceIdentity.load(keystore, "server")
# server side: server_handshake(sock, identity=server)
with Tunnel(sock, client_handshake(sock, expected_identity=server.identity)) as tunnel:
    tunnel.send(b"payload")
    reply = tunnel.recv()
```

Layer 4 — nothing loads unless it is in the signed manifest:

```bash
omnishield allow build ./pkg --out manifest.json      # skips .git, __pycache__, .pyc, venv
omnishield allow verify manifest.json --pub public.json
omnishield allow run manifest.json ./pkg/mod.py --pub public.json
omnishield guard-demo        # fixed 100 ms cadence is flagged as machine timing
```

## Hardening applied in this round

| Issue | Fix |
|---|---|
| SSID could inject `wpa_supplicant` directives | `quote_ssid()` escapes quotes and backslashes; control characters and >32-byte SSIDs are rejected |
| Verify-then-import race (TOCTOU) | `load_module()` reads, hashes, and compiles the same buffer |
| Symlink or `../` escape from the manifest root | `_resolve()` refuses symlinks and any path outside the base directory |
| macOS/Linux filename mismatch | Manifest keys normalised to NFC |
| Replay and counter state readable by other users | Written atomically with `0600` |
| Windows crashing on POSIX permission checks | `POSIX` gate plus a reported `permission_model` |
| Unauthenticated tunnel handshake (MitM) | Optional hybrid-signed transcript, verified against a pinned identity |
| Account takeover by key substitution | `PinStore` trust-on-first-use pinning |
| `__pycache__` polluting manifests | `iter_artifacts()` skips VCS, cache, and build directories |

## Properties, each with a test that attacks it

| Property | Test |
|---|---|
| Removing either signature half is rejected | `test_ml_dsa_half_is_mandatory`, `test_ed25519_half_is_mandatory` |
| Payload or version tampering is rejected | `test_payload_tamper_rejected`, `test_version_hash_tamper_blocked` |
| A version below the pin is refused | `test_protocol_downgrade_blocked`, `test_downgrade_to_wpa2_rejected` |
| Unpinned BSSIDs and unprotected beacons are refused | `test_unpinned_bssid_rejected`, `test_unprotected_beacon_rejected` |
| Replayed signatures, frames, and auth responses are refused | `test_replay_rejected`, `test_replayed_frame_rejected`, `test_replayed_response_rejected` |
| Captured keys cannot open the next frame | `test_captured_keys_cannot_open_the_next_frame` |
| Modified artifacts cannot execute, even after verification | `test_load_module_hashes_the_bytes_it_executes` |
| Symlinks and path escapes are refused | `test_symlink_artifact_rejected`, `test_manifest_entry_cannot_escape_base_dir` |
| A different key cannot answer for a pinned account | `test_pin_store_blocks_key_change` |
| An unsigned or wrongly signed server is rejected | `test_unsigned_handshake_rejected_when_identity_required`, `test_wrong_server_identity_rejected` |
| Machine-regular traffic is flagged | `test_bot_cadence_flagged`, `test_high_rate_flagged` |
| Works over real TCP with rekeying | `test_tcp_ipv4_loopback_with_rekeying`, `test_tcp_with_authenticated_server` |
| Keys with loose permissions are refused | `test_loose_file_permissions_refused` |

```
$ python3 -m pytest
483 passed, 1 skipped in 43.3s
```

The skipped test is the IPv6 loopback check: this container has no `::1`, so the suite reports the skip instead of pretending to cover it.

## Threat model

**Stops:** signature forgery by a classical *or* quantum adversary (as long as one of the two algorithms holds), protocol downgrade, evil-twin and deauth attacks (with PMF enabled), replay of signatures/frames/challenges, execution of unsigned or modified code, credential replay from a phishing site (there is no shared secret to steal), server impersonation on the tunnel (when the identity is pinned), key substitution for a pinned account, and machine-speed abuse a human would not generate.

**Does not stop:** a compromised endpoint (a software keystore can be read by root or malware — only the `tpm2` backend binds the key to hardware), a human deceived by a deepfake (a device key proves *which device* spoke, not that a human was convinced), kernel-level malware, traffic analysis of timing and volume, denial of service, or coercion. Media credentials only prove provenance if the capturing device signs at capture time.

**Key storage honesty:** `open_keystore("auto")` uses TPM 2.0 when available, otherwise a file keystore. The origin is recorded in every attestation (`key_origin`), so a verifier can require `tpm2` and reject software keys.

## Layout

```
omnishield/
  canonical.py     deterministic encoding for signed structures
  hybrid.py        Ed25519 + ML-DSA-44 envelopes, version lock, TTL, replay hooks
  replay.py        persistent single-use nonce cache (0600)
  keystore.py      file backend (POSIX 0700/0600, Windows-aware) and TPM 2.0 backend
  p1_airgap.py     signed network profile, downgrade guard, beacon gate, injection-safe enforcement plan
  p2_identity.py   challenge-response identity, counters, pinning, content credentials
  p3_tunnel.py     X25519 handshake (+ identity binding), AEAD frames, DH ratchet, padding
  p4_allowlist.py  signed manifest, TOCTOU-free import, symlink refusal, inter-arrival guard
  bench.py         measured throughput and latency
  cli.py           `omnishield` command
organism/          Rust core: energy, control, belief, memory, guard, algorithms, JSON-RPC, stealth framing (76 tests)
features/          500-feature ledger with checked evidence (catalog.json + source.txt)
tools/             catalog builder
analysis/          R analysis and report scripts (lib.R, analyse.R, report.R, run.sh)
analysis/out/      committed report: REPORT.md, report.html, tables and charts
omnishield/          security layers, audit log, feature audit, Rust client
tests/             483 Python tests, real crypto and real sockets, no mocks
```

## Muhtasari kwa Kiswahili

Tabaka nne zote zinaendeshwa kwa kweli, si mchoro:

1. **P1 (Wi-Fi):** wasifu uliotiwa saini (SSID, BSSID, kiwango cha chini cha usalama), kizuizi cha downgrade, na mpango halisi wa `wpa_supplicant`/`nmcli`. SSID ya Kiswahili, Kichina au Kiarabu inafanya kazi; SSID yenye nukuu au mstari mpya inakataliwa ili isiingize amri kwenye config.
2. **P2 (Utambulisho):** changamoto ya seva + counter + dirisha la muda + pinning ya ufunguo (mara ya kwanza tu), na content credential ya media.
3. **P3 (Tunnel):** X25519, ChaCha20-Poly1305, ratchet ya DH, padding. Handshake inaweza kutiwa saini na server, hivyo MitM haiwezi kujifanya server.
4. **P4 (Allow-list):** manifest iliyotiwa saini; import inakagua hash ya bytes zile zile itakazotekeleza (hakuna TOCTOU); symlink na `../` zinakataliwa; mwenendo wa mashine unagundulika.

**Organism (Rust):** `organism/` ina energy meter, gradient descent/Adam, Simpson integration, A*, PageRank, MCTS, genetic algorithm, na knapsack — zote zina tests (34). Inafikika kwa JSON-RPC, na state yake inaweza kutiwa saini na ufunguo ule ule wa hybrid. Tabaka za "social", "meta" na "existential" hazipo kwa makusudi: hazina ufafanuzi unaoweza kupimwa.

Ukweli mmoja: ufunguo kwenye faili ni wa programu; ulinzi wa maunzi unapatikana tu kwa backend ya `tpm2` (Linux). Kwenye Windows na macOS funguo ni za programu.
