"""Command line interface for all four layers."""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path
from typing import Any

from .device import DeviceError, require_tpm
from .doctor import run as doctor_run
from .export import export_all
from .features import CatalogError
from .features import audit as feature_audit
from .features import by_group as features_by_group
from .features import by_status as features_by_status
from .features import get as feature_get
from .features import load as load_features
from .federation import beacon_document
from .federation import inventory as net_inventory
from .federation import probe as net_probe
from .hybrid import HybridVerifier, PublicIdentity, SigError, now_ms
from .inspect import process as inspect_process
from .inspect import processes as inspect_processes
from .inspect import read_file as inspect_read_file
from .inspect import snapshot as inspect_snapshot
from .inspect import tree as inspect_tree
from .keystore import KeyStoreError, open_keystore
from .knowledge import KnowledgeStore
from .memory_store import MemoryStoreError, PersistentMemory
from .organism import (
    OrganismClient,
    OrganismError,
    build_binary,
    sign_state,
    verify_state,
)
from .p1_airgap import (
    DowngradeGuard,
    NetworkProfile,
    enforce_plan,
    sign_profile,
    verify_profile,
)
from .p2_identity import (
    CounterStore,
    DeviceIdentity,
    sign_media,
    verify_media,
    verify_response,
)
from .p3_tunnel import RekeyPolicy
from .p3_tunnel import demo as tunnel_demo
from .p4_allowlist import (
    AllowList,
    InterArrivalGuard,
    build_manifest,
    iter_artifacts,
    summarise,
    verify_manifest,
)
from .replay import ReplayCache
from .report import build_report, report_schema
from .status import status as status_report
from .stealth import DEFAULT_CELL as STEALTH_CELL


def _home(args: argparse.Namespace) -> Path:
    base = args.home or os.environ.get("OMNISHIELD_HOME") or str(Path.home() / ".omnishield")
    return Path(base).expanduser()


def _keystore(args: argparse.Namespace):
    return open_keystore(args.backend, _home(args) / "keys")


def _identity(args: argparse.Namespace) -> DeviceIdentity:
    counters = CounterStore(_home(args) / "counters.json")
    return DeviceIdentity.load(_keystore(args), args.name, counters=counters)


def _public(path: str | os.PathLike[str]) -> PublicIdentity:
    return PublicIdentity.from_dict(json.loads(Path(path).read_text(encoding="utf-8")))


def _dump(document: Any, path: str | None) -> None:
    text = json.dumps(document, indent=2, sort_keys=True)
    if path:
        Path(path).write_text(text + "\n", encoding="utf-8")
    else:
        print(text)


def _read(path: str) -> bytes:
    return Path(path).read_bytes()


def cmd_keygen(args: argparse.Namespace) -> int:
    hardware = require_tpm() if getattr(args, "hardware", False) else None
    store = _keystore(args)
    identity = DeviceIdentity.create(store, args.name, counters=CounterStore(_home(args) / "counters.json"))
    document = identity.public_document()
    if hardware is not None:
        document = {**document, "hardware": {"bound": True, "device": hardware}}
    _dump(document, args.out)
    print(f"key stored in {store.origin} backend as {args.name!r}", file=sys.stderr)
    if hardware is not None:
        print(f"key bound to {hardware}", file=sys.stderr)
    return 0


def cmd_sign(args: argparse.Namespace) -> int:
    identity = _identity(args)
    envelope = identity.signer.sign(_read(args.file), domain=args.domain)
    _dump(envelope, args.out)
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    envelope = json.loads(Path(args.signature).read_text(encoding="utf-8"))
    identity = _public(args.pub) if args.pub else _identity(args).identity
    HybridVerifier(identity).verify(
        envelope,
        _read(args.file),
        expected_domain=args.domain,
        replay=ReplayCache(_home(args) / "replay.json") if args.replay else None,
    )
    print("signature valid", file=sys.stderr)
    return 0


def cmd_net_sign(args: argparse.Namespace) -> int:
    profile = NetworkProfile(
        ssid=args.ssid,
        bssids=tuple(args.bssid or ()),
        min_security=args.min_security,
        allowed_versions=tuple(args.allow or (args.min_security,)),
    )
    _dump(sign_profile(profile, _identity(args).signer), args.out)
    return 0


def cmd_net_verify(args: argparse.Namespace) -> int:
    document = json.loads(Path(args.profile).read_text(encoding="utf-8"))
    profile = verify_profile(
        document,
        HybridVerifier(_identity(args).identity),
        replay=ReplayCache(_home(args) / "replay.json") if args.replay else None,
    )
    _dump(profile.to_dict(), None)
    return 0


def cmd_net_enforce(args: argparse.Namespace) -> int:
    document = json.loads(Path(args.profile).read_text(encoding="utf-8"))
    profile = verify_profile(document, HybridVerifier(_identity(args).identity))
    plan = enforce_plan(profile, interface=args.interface)
    print(plan["wpa_supplicant.conf"])
    for command in plan["nmcli"]:
        print(f"# {command}")
    for note in plan["notes"]:
        print(f"# note: {note}")
    return 0


def cmd_net_guard(args: argparse.Namespace) -> int:
    document = json.loads(Path(args.profile).read_text(encoding="utf-8"))
    guard = DowngradeGuard(verify_profile(document, HybridVerifier(_identity(args).identity)))
    chosen = guard.negotiate(args.offered)
    print(json.dumps({"negotiated": chosen, "lock": guard.lock_hash()}, indent=2))
    return 0


def cmd_id_pub(args: argparse.Namespace) -> int:
    _dump(_identity(args).public_document(), args.out)
    return 0


def cmd_id_respond(args: argparse.Namespace) -> int:
    document = _identity(args).respond(bytes.fromhex(args.challenge), args.context)
    _dump(document, args.out)
    return 0


def cmd_id_verify(args: argparse.Namespace) -> int:
    document = json.loads(Path(args.response).read_text(encoding="utf-8"))
    payload = verify_response(
        document,
        _public(args.pub),
        server_nonce=bytes.fromhex(args.challenge),
        expected_context=args.context,
        counters=CounterStore(args.counters) if args.counters else None,
    )
    _dump(payload, None)
    return 0


def cmd_id_sign_media(args: argparse.Namespace) -> int:
    document = sign_media(args.file, _identity(args), capture_origin=args.capture_origin)
    _dump(document, args.out)
    return 0


def cmd_id_verify_media(args: argparse.Namespace) -> int:
    document = json.loads(Path(args.sidecar).read_text(encoding="utf-8"))
    payload = verify_media(args.file, document, _public(args.pub))
    _dump(payload, None)
    return 0


def cmd_tunnel_demo(args: argparse.Namespace) -> int:
    policy = RekeyPolicy(packets=args.packets, seconds=args.seconds)
    identity = _identity(args) if args.authenticate else None
    for line in tunnel_demo(policy=policy, identity=identity):
        print(line)
    if identity is not None:
        print(f"server identity verified: {identity.device_id[:16]}...")
    return 0


def cmd_allow_build(args: argparse.Namespace) -> int:
    root = Path(args.directory).resolve()
    paths = [root / name for name in args.file] if args.file else iter_artifacts(root)
    if not paths:
        raise SigError("no files to add to the manifest")
    _dump(build_manifest(paths, _identity(args).signer, base_dir=root), args.out)
    return 0


def cmd_allow_verify(args: argparse.Namespace) -> int:
    document = json.loads(Path(args.manifest).read_text(encoding="utf-8"))
    entries = verify_manifest(
        document,
        HybridVerifier(_public(args.pub)),
        check_files=not args.no_check_files,
    )
    print(summarise(entries), file=sys.stderr)
    _dump([entry.to_dict() for entry in entries], None)
    return 0


def cmd_allow_run(args: argparse.Namespace) -> int:
    document = json.loads(Path(args.manifest).read_text(encoding="utf-8"))
    allow = AllowList(document, HybridVerifier(_public(args.pub)))
    module = allow.load_module(args.file)
    print(f"loaded {module.__name__} from allow-listed {args.file}", file=sys.stderr)
    return 0


def cmd_guard_demo(args: argparse.Namespace) -> int:
    guard = InterArrivalGuard()
    now = now_ms()
    print("fixed 100 ms cadence:")
    for index in range(1, 12):
        decision = guard.observe(now + index * 100)
        print(f"  #{index:02d} allow={decision.allow} reason={decision.reason}")
    return 0


def cmd_organism_build(args: argparse.Namespace) -> int:
    path = build_binary(release=not args.debug)
    print(f"built {path}", file=sys.stderr)
    return 0


def cmd_organism_discover(args: argparse.Namespace) -> int:
    with OrganismClient(args.binary) as client:
        _dump(client.discover(), args.out)
    return 0


def cmd_organism_call(args: argparse.Namespace) -> int:
    try:
        params = json.loads(args.params)
    except json.JSONDecodeError as exc:
        raise ValueError(f"params must be JSON: {exc}") from exc
    with OrganismClient(args.binary) as client:
        _dump(client.call(args.method, params), None)
    return 0


def cmd_organism_state(args: argparse.Namespace) -> int:
    with OrganismClient(args.binary) as client:
        document = sign_state(client, _identity(args).signer) if args.sign else client.state()
    _dump(document, args.out)
    return 0


def cmd_organism_verify_state(args: argparse.Namespace) -> int:
    document = json.loads(Path(args.file).read_text(encoding="utf-8"))
    _dump(verify_state(document, _public(args.pub)), None)
    return 0


def cmd_features_audit(args: argparse.Namespace) -> int:
    report = feature_audit()
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True, ensure_ascii=False))
        return 0 if report["ok"] else 1
    print(
        f"features: {report['total']}  built: {report['built']}  "
        f"coverage: {report['coverage']:.0%}"
    )
    for status, count in report["counts"].items():
        print(f"  {status:16s} {count}")
    if report["problems"]:
        print("problems:")
        for problem in report["problems"]:
            print(f"  ! {problem}")
        return 1
    return 0


def cmd_features_list(args: argparse.Namespace) -> int:
    if args.status:
        items = features_by_status(args.status)
    elif args.group:
        items = features_by_group(args.group)
    else:
        items = load_features()
    if args.json:
        print(
            json.dumps(
                [
                    {
                        "id": feature.id,
                        "group": feature.group,
                        "name": feature.name,
                        "name_sw": feature.name_sw,
                        "status": feature.status,
                        "evidence": feature.evidence,
                        "reason": feature.reason,
                    }
                    for feature in items
                ],
                indent=2,
                ensure_ascii=False,
                sort_keys=True,
            )
        )
        return 0
    for feature in items:
        print(f"{feature.id:3d} [{feature.status:15s}] {feature.name}")
    return 0


def cmd_features_show(args: argparse.Namespace) -> int:
    feature = feature_get(args.id)
    print(
        json.dumps(
            {
                "id": feature.id,
                "group": feature.group,
                "group_sw": feature.group_sw,
                "name": feature.name,
                "name_sw": feature.name_sw,
                "status": feature.status,
                "evidence": feature.evidence,
                "reason": feature.reason,
            },
            indent=2,
            ensure_ascii=False,
        )
    )
    return 0



def cmd_memory_insert(args: argparse.Namespace) -> int:
    store = PersistentMemory(args.db, capacity=args.capacity)
    identifier = store.insert(
        args.content,
        args.embedding,
        salience=args.salience,
        emotion=args.emotion,
        now=args.now_ms,
    )
    print(json.dumps({"id": identifier, "snapshot": store.digest()}, sort_keys=True))
    return 0


def cmd_memory_search(args: argparse.Namespace) -> int:
    store = PersistentMemory(args.db)
    found = store.search(args.embedding, limit=args.limit, now=args.now_ms)
    print(json.dumps(found, indent=2, ensure_ascii=False))
    return 0


def cmd_memory_stats(args: argparse.Namespace) -> int:
    print(json.dumps(PersistentMemory(args.db).stats(), sort_keys=True))
    return 0


def cmd_memory_forget(args: argparse.Namespace) -> int:
    store = PersistentMemory(args.db)
    store.forget(args.id)
    print(json.dumps({"forgotten": args.id}, sort_keys=True))
    return 0


def cmd_memory_verify(args: argparse.Namespace) -> int:
    print(json.dumps(PersistentMemory(args.db).verify(), sort_keys=True))
    return 0



def cmd_status(args: argparse.Namespace) -> int:
    report = status_report()
    if args.json:
        print(json.dumps(report, indent=2, ensure_ascii=False, sort_keys=True))
    else:
        print("OmniShield")
        for component in report["components"]:
            mark = "ok " if component["ok"] else "MISS"
            print(f"  [{mark}] {component['name']:30s} {component['detail']}")
        features = report["features"]
        binary = report["organism_binary"] or "not built"
        print(f"  organism binary: {binary}")
        print(f"  features: {features['built']}/{features['total']} built ({features['coverage']}%)")
    return 0 if report["ok"] else 1


def cmd_doctor(args: argparse.Namespace) -> int:
    report = doctor_run()
    if getattr(args, "jsonl", False):
        for check in report["checks"]:
            print(json.dumps(check, sort_keys=True))
        return 0 if report["ok"] else 1
    if args.json:
        print(json.dumps(report, indent=2, ensure_ascii=False, sort_keys=True))
    else:
        for check in report["checks"]:
            mark = "PASS" if check["ok"] else "FAIL"
            print(f"  {mark}  {check['check']:14s} {check['ms']:5d} ms  {check['detail']}")
        passed = sum(1 for check in report["checks"] if check["ok"])
        print(f"\n{passed}/{len(report['checks'])} checks passed in {report['duration_ms']} ms")
    return 0 if report["ok"] else 1



def cmd_export(args: argparse.Namespace) -> int:
    manifest = export_all(
        args.out,
        memory_db=args.memory,
        payments_ledger=args.payments,
        audit_log=args.audit,
    )
    print(json.dumps(manifest, indent=2, sort_keys=True))
    return 0


def cmd_federation_inventory(args: argparse.Namespace) -> int:
    document = net_inventory(arp=args.arp, tcp=args.tcp)
    if args.json:
        print(json.dumps(document, indent=2, sort_keys=True))
        return 0
    table = document["neighbours"]
    print(f"neighbours: {document['neighbour_count']}")
    if not table["available"]:
        print(f"  ({table['reason']})")
    for entry in table["entries"]:
        mark = " " if entry["complete"] else "?"
        print(f" {mark} {entry['ip']:15s} {entry['mac']:17s} {entry['device']}")
    print(f"listening: {document['listening_count']}")
    if not document["listening"]["available"]:
        print(f"  ({document['listening']['reason']})")
    for entry in document["listening"]["ports"]:
        print(f"   port {entry['port']:5d}  {', '.join(entry['addresses'])}")
    return 0


def cmd_federation_probe(args: argparse.Namespace) -> int:
    result = net_probe(args.host, args.port, timeout=args.timeout)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["open"] else 1


def cmd_federation_beacon(args: argparse.Namespace) -> int:
    signer = _identity(args).signer
    document = beacon_document(
        signer.public_identity.key_id.hex(),
        signer=signer,
        capabilities=args.capability,
        port=args.port,
        ttl_s=args.ttl,
    )
    print(json.dumps(document, indent=2, sort_keys=True))
    return 0


def _knowledge_store(args: argparse.Namespace) -> KnowledgeStore:
    base = Path(args.state) if args.state else Path(os.environ.get("OMNISHIELD_HOME", Path.home() / ".omnishield"))
    return KnowledgeStore.open(base / "knowledge.jsonl")


def cmd_answer_ask(args: argparse.Namespace) -> int:
    from .answer import analyse
    from .knowledge import KnowledgeStore

    store = KnowledgeStore.open(args.store)
    passages = [{"text": item.get("text", ""), "title": item.get("title", ""), "source": item.get("source", "")} for item in store.items]
    print(json.dumps(analyse(args.question, passages), indent=2, ensure_ascii=False))
    return 0


def cmd_lang_id(args: argparse.Namespace) -> int:
    from .language import identify

    print(json.dumps(identify(args.text), indent=2, ensure_ascii=False))
    return 0


def cmd_lang_follow(args: argparse.Namespace) -> int:
    from .knowledge import KnowledgeStore
    from .language import ConversationTracker

    tracker = ConversationTracker(window=args.window)
    for line in Path(args.file).read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        record = json.loads(line)
        tracker.observe(record["speaker"], record["text"])
    document = tracker.summary()
    if args.store:
        document["learned"] = tracker.learn(KnowledgeStore.open(args.store))
    print(json.dumps(document, indent=2, ensure_ascii=False))
    return 0


def cmd_stream_bench(args: argparse.Namespace) -> int:
    from .stream import disk_benchmark

    print(json.dumps(disk_benchmark(args.size_mb, directory=args.dir), indent=2))
    return 0


def cmd_stream_fetch(args: argparse.Namespace) -> int:
    from .stream import parallel_fetch

    urls = [
        line.strip()
        for line in Path(args.urls).read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]
    print(json.dumps(parallel_fetch(urls, workers=args.workers, allow_private=args.allow_private), indent=2))
    return 0


def cmd_stream_telemetry(args: argparse.Namespace) -> int:
    from .stream import Telemetry, simulate_air

    telemetry = Telemetry(args.path, window=args.window)
    if args.simulate:
        for sample in simulate_air(args.minutes):
            telemetry.ingest(sample)
    print(json.dumps({"stats": telemetry.stats(), "alerts": telemetry.alerts()}, indent=2))
    return 0


def cmd_speech_say(args: argparse.Namespace) -> int:
    from .speech import speak

    print(json.dumps(speak(args.text, args.out, speed=args.speed), indent=2))
    return 0


def cmd_speech_train(args: argparse.Namespace) -> int:
    from .speech import KeywordSpotter
    from .vision import read_wav

    spotter = KeywordSpotter(threshold=args.threshold)
    wav = read_wav(args.wav)
    print(json.dumps(spotter.train(args.word, wav["samples"], wav["rate"]), indent=2))
    return 0


def cmd_speech_listen(args: argparse.Namespace) -> int:
    from .speech import KeywordSpotter, formant_speak, listen

    spotter = KeywordSpotter(threshold=args.threshold)
    for word in args.words.split(","):
        spotter.train(word.strip(), formant_speak(word.strip()))
    print(json.dumps(listen(args.wav, spotter), indent=2))
    return 0


def cmd_sovereign_status(args: argparse.Namespace) -> int:
    from .sovereign import status

    print(json.dumps(status(), indent=2))
    return 0


def cmd_sovereign_pipeline(args: argparse.Namespace) -> int:
    from .sovereign import pipeline

    print(json.dumps(pipeline(rights=args.rights), indent=2))
    return 0


def cmd_mlp_demo(args: argparse.Namespace) -> int:
    from .mlp import demo

    print(json.dumps(demo(epochs=args.epochs), indent=2))
    return 0


def cmd_neuron_demo(args: argparse.Namespace) -> int:
    from .neuron import demo

    print(json.dumps(demo(dimension=args.dimension, repeats=args.repeats), indent=2))
    return 0


def cmd_swarm_demo(args: argparse.Namespace) -> int:
    from .swarm import demo

    print(json.dumps(demo(samples=args.samples), indent=2))
    return 0


def cmd_r_export(args: argparse.Namespace) -> int:
    from .knowledge import KnowledgeStore
    from .language import ConversationTracker
    from .rdata import export_all_csv

    tracker = None
    if args.conversation:
        tracker = ConversationTracker(window=args.window)
        for line in Path(args.conversation).read_text(encoding="utf-8").splitlines():
            if line.strip():
                record = json.loads(line)
                tracker.observe(record["speaker"], record["text"])
    questions = []
    if args.questions:
        questions = [line.strip() for line in Path(args.questions).read_text(encoding="utf-8").splitlines() if line.strip()]
    passages = []
    if args.store:
        store = KnowledgeStore.open(args.store)
        passages = [{"text": item.get("text", ""), "source": item.get("source", ""), "title": item.get("title", "")} for item in store.items]
    print(json.dumps(export_all_csv(args.out, tracker=tracker, questions=questions, passages=passages), indent=2))
    return 0


def cmd_r_analyse(args: argparse.Namespace) -> int:
    from .rdata import analyse_with_r

    print(json.dumps(analyse_with_r(args.dir), indent=2))
    return 0


def cmd_skill_list(args: argparse.Namespace) -> int:
    from .skills import registry

    print(json.dumps(registry(), indent=2, ensure_ascii=False))
    return 0


def cmd_skill_run(args: argparse.Namespace) -> int:
    from .skills import run

    params = json.loads(args.params) if args.params else {}
    print(json.dumps(run(args.name, params), indent=2, ensure_ascii=False))
    return 0


def cmd_omni_say(args: argparse.Namespace) -> int:
    from .omnilang import Lexicon, speak

    lexicon = Lexicon(args.lexicon)
    for concept in (args.subject, args.verb) + ((args.object,) if args.object else ()):
        lexicon.learn(concept)
    lexicon.save()
    print(json.dumps({"omni": speak(lexicon, args.subject, args.verb, args.object, tense=args.tense)}, indent=2))
    return 0


def cmd_omni_parse(args: argparse.Namespace) -> int:
    from .omnilang import Lexicon, gloss, parse

    lexicon = Lexicon(args.lexicon)
    print(json.dumps({"gloss": gloss(lexicon, args.text), "parse": parse(lexicon, args.text)}, indent=2, ensure_ascii=False))
    return 0


def cmd_omni_translate(args: argparse.Namespace) -> int:
    from .omnilang import Lexicon, translate

    lexicon = Lexicon(args.lexicon)
    result = translate(lexicon, args.text)
    lexicon.save()
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0


def cmd_study_run(args: argparse.Namespace) -> int:
    from .knowledge import KnowledgeStore
    from .omnilang import Lexicon
    from .selfstudy import run

    passages = [json.loads(line) for line in Path(args.file).read_text(encoding="utf-8").splitlines() if line.strip()]
    store = KnowledgeStore.open(args.store)
    result = run(passages, store, Lexicon(args.lexicon), rounds=args.rounds)
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0


def cmd_mesh_keygen(args: argparse.Namespace) -> int:
    from .net import keypair

    keys = keypair()
    target = Path(args.out)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(keys, indent=1), encoding="utf-8")
    target.chmod(0o600)
    print(json.dumps({"path": str(target), "public": keys["public"]}, indent=2))
    return 0


def _read_key(path: str | None) -> str | None:
    if not path:
        return None
    return json.loads(Path(path).read_text(encoding="utf-8"))["private"]


def cmd_mesh_chat(args: argparse.Namespace) -> int:
    from .knowledge import KnowledgeStore
    from .net import Node, envelope

    host, _, port = args.peer.partition(":")
    node = Node(args.id, store=KnowledgeStore.open(args.store), private_key=_read_key(args.key))
    reply = node.send(host or "127.0.0.1", int(port), envelope("chat", node.id, {"text": args.text}, private_key=node.private_key))
    print(json.dumps(reply, indent=2, ensure_ascii=False))
    return 0


def cmd_think_ask(args: argparse.Namespace) -> int:
    from .knowledge import KnowledgeStore
    from .think import think

    print(json.dumps(think(args.question, KnowledgeStore.open(args.store), depth=args.depth), indent=2, ensure_ascii=False))
    return 0


def cmd_corpus_learn(args: argparse.Namespace) -> int:
    from .corpus import learn_book, learn_dictionary, learn_directory
    from .knowledge import KnowledgeStore
    from .omnilang import Lexicon

    store = KnowledgeStore.open(args.store)
    lexicon = Lexicon(args.lexicon)
    if args.directory:
        result = learn_directory(store, lexicon, args.directory)
    elif args.dictionary:
        result = learn_dictionary(store, lexicon, args.dictionary)
    elif args.book:
        result = learn_book(store, lexicon, args.book)
    else:
        raise SystemExit("give --book, --dictionary or --directory")
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0


def cmd_net_gossip(args: argparse.Namespace) -> int:
    from .knowledge import KnowledgeStore
    from .net import Node

    host, _, port = args.peer.partition(":")
    node = Node(args.id, store=KnowledgeStore.open(args.store), private_key=_read_key(args.key))
    print(json.dumps(node.gossip([(host or "127.0.0.1", int(port))]), indent=2, ensure_ascii=False))
    return 0


def cmd_net_serve(args: argparse.Namespace) -> int:
    import time as clock

    from .knowledge import KnowledgeStore
    from .net import Node

    node = Node(
        args.id,
        host=args.host,
        port=args.port,
        store=KnowledgeStore.open(args.store),
        private_key=_read_key(args.key),
        require_signature=args.require_signature,
    )
    port = node.start()
    print(json.dumps({"node": node.id, "port": port, "seconds": args.seconds}, indent=2))
    clock.sleep(args.seconds)
    node.stop()
    print(json.dumps({"received": len(node.received), "items": len(node.store.items)}, indent=2))
    return 0


def cmd_three_pathtrace(args: argparse.Namespace) -> int:
    from .three_d import pathtrace

    print(json.dumps(pathtrace(args.scene, args.out), indent=2))
    return 0


def cmd_three_scene(args: argparse.Namespace) -> int:
    from .three_d import scene3d

    rendered = scene3d(
        args.width,
        args.height,
        samples=args.samples,
        engine=args.engine,
        threads=args.threads,
        angle=args.angle,
        aperture=args.aperture,
    )
    path = rendered["canvas"].save_png(args.out)
    print(json.dumps({**{k: v for k, v in rendered.items() if k != "canvas"}, "path": str(path)}, indent=2))
    return 0


def cmd_three_video(args: argparse.Namespace) -> int:
    from .three_d import video

    result = video(args.frames, preset_name=args.preset, aperture=args.aperture)
    import shutil

    shutil.move(str(result["gif"]), args.out)
    print(
        json.dumps(
            {
                "path": args.out,
                "frames": result["frames"],
                "preset": result["preset"],
                "mean_frame_ms": result["mean_frame_ms"],
                "min_frame_ms": result["min_frame_ms"],
                "encode_ms": result["encode_ms"],
                "total_ms": result["total_ms"],
            },
            indent=2,
        )
    )
    return 0


def cmd_three_orbit(args: argparse.Namespace) -> int:
    from .render import save_gif
    from .three_d import orbit

    frames = orbit(args.frames, args.width, args.height)
    path = save_gif(frames, args.out, delay_cs=args.delay)
    print(json.dumps({"path": str(path), "frames": len(frames), "bytes": path.stat().st_size}, indent=2))
    return 0


def cmd_three_simulate(args: argparse.Namespace) -> int:
    from .three_d import simulate_pendulum, simulate_projectile

    if args.kind == "pendulum":
        result = simulate_pendulum(damping=args.damping)
    else:
        result = simulate_projectile(drag=args.drag)
    rows = result.pop("rows")
    print(json.dumps({**result, "samples": len(rows), "first": rows[:2], "last": rows[-2:]}, indent=2))
    return 0


def cmd_three_plot(args: argparse.Namespace) -> int:
    from .three_d import plot3d, simulate_projectile

    if args.source == "projectile":
        rows = simulate_projectile().get("rows", [])
        points = [(row["x"], row["y"], row["t"]) for row in rows]
    else:
        points = [(float(part.split(":")[0]), float(part.split(":")[1]), float(part.split(":")[2])) for part in args.points.split(";")]
    path = plot3d(points, title=args.title).save_png(args.out)
    print(json.dumps({"path": str(path), "points": len(points)}, indent=2))
    return 0


def cmd_imagery_daily(args: argparse.Namespace) -> int:
    from .imagery import daily as imagery_daily
    from .knowledge import KnowledgeStore

    feeds = [
        line.strip()
        for line in Path(args.feeds).read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]
    state = Path(args.state)
    store = KnowledgeStore.open(state / "knowledge.jsonl")
    document = imagery_daily(
        feeds,
        store,
        out_dir=args.out,
        seen_path=state / "seen-images.json",
        limit=args.limit,
        allow_private=args.allow_private,
    )
    print(json.dumps(document, indent=2, ensure_ascii=False))
    return 0


def cmd_render_scene(args: argparse.Namespace) -> int:
    from .render import scene

    rendered = scene(args.width, args.height, samples=args.samples, engine=args.engine)
    path = rendered["canvas"].save_png(args.out)
    print(
        json.dumps(
            {
                "path": str(path),
                "engine": rendered["engine"],
                "samples": rendered["samples"],
                "elapsed_ms": rendered["elapsed_ms"],
                "pixels_per_second": rendered["pixels_per_second"],
                "bytes": path.stat().st_size,
            },
            indent=2,
        )
    )
    return 0


def cmd_worship_daily(args: argparse.Namespace) -> int:
    from .notify import Notifier, load_recipients, message_for
    from .worship import daily, journal_stats

    journal = args.journal or str(Path(args.out) / "journal.jsonl")
    entry = daily(args.out, journal_path=journal, day=args.day)
    document: dict[str, Any] = {"entry": entry, "stats": journal_stats(journal)}
    if args.notify:
        recipients = load_recipients(args.notify)
        notifier = Notifier(Path(args.out) / "notify-state.json", dry_run=not args.send)
        document["notify"] = notifier.send(recipients, message_for(entry))
    print(json.dumps(document, indent=2, ensure_ascii=False, sort_keys=True))
    return 0


def cmd_worship_sing(args: argparse.Namespace) -> int:
    from .signal import write_wav
    from .worship import hymn_samples

    samples = hymn_samples(args.theme, rate=args.rate)
    path = write_wav(args.out, samples, rate=args.rate)
    print(
        json.dumps(
            {"path": str(path), "theme": args.theme, "seconds": round(len(samples) / args.rate, 2)},
            indent=2,
        )
    )
    return 0


def cmd_worship_journal(args: argparse.Namespace) -> int:
    from .worship import journal_stats, read_journal

    journal = args.journal or str(Path.home() / ".omnishield" / "worship.jsonl")
    print(
        json.dumps(
            {"stats": journal_stats(journal), "entries": read_journal(journal)[-7:]},
            indent=2,
            ensure_ascii=False,
        )
    )
    return 0


def cmd_notify_test(args: argparse.Namespace) -> int:
    from .notify import Notifier, load_recipients, message_for
    from .worship import office

    recipients = load_recipients(args.to)
    notifier = Notifier(args.state or "notify-state.json", dry_run=not args.send)
    result = notifier.send(recipients, message_for(office(day=0)))
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0


def cmd_thermal_status(args: argparse.Namespace) -> int:
    from .thermal import Governor

    print(json.dumps(Governor(target=args.target).state(), indent=2))
    return 0


def cmd_render_chart(args: argparse.Namespace) -> int:
    from .render import chart

    values = [float(part) for part in args.series.split(",") if part.strip()]
    path = chart(values, title=args.title).save_png(args.out)
    print(json.dumps({"path": str(path), "bytes": path.stat().st_size}, indent=2))
    return 0


def cmd_render_art(args: argparse.Namespace) -> int:
    from .render import art

    path = art(args.seed, width=args.width, height=args.height).save_png(args.out)
    print(json.dumps({"path": str(path), "bytes": path.stat().st_size, "seed": args.seed}, indent=2))
    return 0


def cmd_render_video(args: argparse.Namespace) -> int:
    from .render import animate, save_gif

    frames = animate(frames=args.frames, width=args.width, height=args.height, seed=args.seed)
    path = save_gif(frames, args.out, delay_cs=args.delay)
    print(
        json.dumps(
            {"path": str(path), "bytes": path.stat().st_size, "frames": len(frames)}, indent=2
        )
    )
    return 0


def cmd_signal_synth(args: argparse.Namespace) -> int:
    from .signal import synthesise, write_wav

    frequencies = [float(part) for part in args.freq.split(",") if part.strip()]
    samples = synthesise(frequencies, args.seconds, rate=args.rate)
    path = write_wav(args.out, samples, rate=args.rate)
    print(json.dumps({"path": str(path), "samples": len(samples), "rate": args.rate}, indent=2))
    return 0


def cmd_signal_clean(args: argparse.Namespace) -> int:
    from .signal import clean, write_wav
    from .vision import read_wav

    read = read_wav(args.input)
    result = clean(read["samples"], rate=read["rate"])
    path = write_wav(args.out, result["samples"], rate=read["rate"])
    document = {key: value for key, value in result.items() if key != "samples"}
    document["path"] = str(path)
    print(json.dumps(document, indent=2, sort_keys=True))
    return 0


def cmd_doc_report(args: argparse.Namespace) -> int:
    from .docgen import report
    from .features import audit as feature_audit
    from .predict import predict_system
    from .render import chart
    from .status import status as status_report

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    audit_doc = feature_audit()
    components = status_report()["components"]
    counts = audit_doc["counts"]
    prediction = predict_system(samples=5)
    chart_path = chart(
        [counts["implemented"], counts["partial"], counts["external"], counts["refused"]],
        title="Feature status",
    ).save_png(out / "chart.png")
    groups = sorted(
        audit_doc["groups"].items(),
        key=lambda pair: -(pair[1]["implemented"] + pair[1]["partial"]),
    )[:8]
    blocks = [
        {"type": "h1", "text": "OmniShield Status Report"},
        {
            "type": "p",
            "text": (
                f"This report was generated from the repository on "
                f"{time.strftime('%Y-%m-%d')}. Every number below comes from a live "
                f"audit of the feature ledger, the component health check, the doctor "
                f"suite and a measured prediction run."
            ),
        },
        {"type": "h2", "text": "Executive summary"},
        {
            "type": "p",
            "text": (
                f"{audit_doc['total']} features are tracked. {audit_doc['built']} have running "
                f"code behind them ({audit_doc['coverage']:.1%}), of which "
                f"{counts['implemented']} are implemented and {counts['partial']} are partial. "
                f"{counts['external']} need hardware or a service that is not in this repository, "
                f"and {counts['refused']} are refused because they have no testable definition. "
                f"{sum(1 for component in components if component['ok'])} of "
                f"{len(components)} components pass their checks."
            ),
        },
        {"type": "h2", "text": "Coverage by group"},
        {
            "type": "table",
            "rows": [["Group", "Implemented", "Partial", "External", "Refused"]]
            + [
                [group, bucket["implemented"], bucket["partial"], bucket["external"], bucket["refused"]]
                for group, bucket in groups
            ],
        },
        {"type": "image", "path": str(chart_path)},
        {"type": "h2", "text": "Component health"},
        {
            "type": "table",
            "rows": [["Layer", "Component", "Status"]]
            + [[component["layer"], component["name"], "pass" if component["ok"] else "fail"] for component in components[:14]],
        },
        {"type": "h2", "text": "Prediction against reality"},
        {
            "type": "table",
            "rows": [["Reading", "Predicted", "Observed", "Error"]]
            + [
                [key, entry["predicted"], entry["observed"], entry["error"]]
                for key, entry in prediction["reality"]["keys"].items()
            ],
        },
        {
            "type": "p",
            "text": (
                f"Mean absolute error was {prediction['reality']['mae']} with verdict "
                f"'{prediction['reality']['verdict']}'. The prediction was made from "
                f"{prediction['samples'] - 1} samples and then checked against the next real reading."
            ),
        },
        {"type": "h2", "text": "How this report was made"},
        {
            "type": "code",
            "text": "omnishield doc report --out analysis/out\n"
            "docx, xlsx, pptx and pdf are written directly by omnishield/docgen.py",
        },
        {"type": "h2", "text": "What is not claimed"},
        {"type": "bullet", "text": "No consciousness, feelings or human equivalence."},
        {"type": "bullet", "text": "External features stay external until the hardware exists."},
        {"type": "bullet", "text": "Refused features stay refused; they are not relabelled."},
    ]
    sheets = {
        "Coverage": [["Group", "Implemented", "Partial", "External", "Refused"]]
        + [
            [group, bucket["implemented"], bucket["partial"], bucket["external"], bucket["refused"]]
            for group, bucket in sorted(audit_doc["groups"].items())
        ],
        "Components": [["Layer", "Component", "Evidence", "Status"]]
        + [[component["layer"], component["name"], component["evidence"], component["ok"]] for component in components],
        "Prediction": [["Reading", "Predicted", "Observed", "Error"]]
        + [
            [key, entry["predicted"], entry["observed"], entry["error"]]
            for key, entry in prediction["reality"]["keys"].items()
        ],
    }
    slides = [
        {
            "title": "OmniShield",
            "lines": [
                f"{audit_doc['built']} of {audit_doc['total']} features built",
                f"{counts['implemented']} implemented, {counts['partial']} partial",
                "Measured, not asserted",
            ],
            "dark": True,
        },
        {
            "title": "Coverage",
            "lines": [
                f"{audit_doc['coverage']:.1%} coverage",
                f"{counts['external']} external, {counts['refused']} refused",
                f"{sum(1 for component in components if component['ok'])}/{len(components)} components pass",
            ],
        },
        {
            "title": "What is not claimed",
            "lines": [
                "No consciousness or feelings",
                "External stays external",
                "Refused stays refused",
            ],
        },
    ]
    written = report(
        "OmniShield Status Report",
        blocks,
        out_dir=out,
        sheets=sheets,
        slides=slides,
    )
    print(json.dumps(written, indent=2, sort_keys=True))
    return 0


def cmd_predict_system(args: argparse.Namespace) -> int:
    from .predict import predict_system

    document = predict_system(samples=args.samples, interval_s=args.interval)
    if args.json:
        print(json.dumps(document, indent=2, sort_keys=True))
        return 0
    reality = document["reality"]
    print(f"predicted from {document['samples'] - 1} samples, then measured:")
    for key, entry in reality["keys"].items():
        print(
            f"  {key:16s} predicted {entry['predicted']:>8}  observed {entry['observed']:>8}  "
            f"error {entry['error']:>8}"
        )
    print(f"  mae {reality['mae']}  verdict {reality['verdict']}")
    return 0 if reality["verdict"] == "close" else 1


def cmd_learn_add(args: argparse.Namespace) -> int:
    result = _knowledge_store(args).add(
        args.text, source=args.source, title=args.title or "", tags=args.tag or []
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


def cmd_learn_page(args: argparse.Namespace) -> int:
    from .ingest import ingest_page

    result = ingest_page(
        args.url, _knowledge_store(args), allow_private=args.allow_private, tags=args.tag or []
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


def cmd_learn_feed(args: argparse.Namespace) -> int:
    from .ingest import ingest_feed

    result = ingest_feed(
        args.url,
        _knowledge_store(args),
        limit=args.limit,
        allow_private=args.allow_private,
        tags=args.tag or [],
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


def cmd_learn_search(args: argparse.Namespace) -> int:
    results = _knowledge_store(args).search(args.query, limit=args.limit)
    if args.json:
        print(json.dumps(results, indent=2, sort_keys=True))
        return 0
    for entry in results:
        print(f"{entry['score']:7.2f}  {entry['title'][:60]}  [{entry['source'][:50]}]")
    return 0


def cmd_learn_stats(args: argparse.Namespace) -> int:
    from .brain import curiosity

    store = _knowledge_store(args)
    document = {"stats": store.stats(), "curiosity": curiosity(store, limit=5)}
    print(json.dumps(document, indent=2, sort_keys=True))
    return 0


def cmd_learn_cycle(args: argparse.Namespace) -> int:
    from .brain import DailyCycle, write_cycle_log

    feeds = [
        line.strip()
        for line in Path(args.feeds).read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]
    store = _knowledge_store(args)
    cycle = DailyCycle(
        store,
        feeds=feeds,
        allow_private=args.allow_private,
        limit=args.limit,
        tags=args.tag or [],
    )
    document = cycle.run()
    base = Path(args.state) if args.state else Path(os.environ.get("OMNISHIELD_HOME", Path.home() / ".omnishield"))
    write_cycle_log(base / "cycles.jsonl", document)
    print(json.dumps(document, indent=2, sort_keys=True))
    return 0 if not document["failed_feeds"] else 1


def cmd_learn_review(args: argparse.Namespace) -> int:
    print(json.dumps(_knowledge_store(args).review(limit=args.limit), indent=2, sort_keys=True))
    return 0


def cmd_learn_grade(args: argparse.Namespace) -> int:
    result = _knowledge_store(args).grade(args.id, args.grade)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


def cmd_inspect_file(args: argparse.Namespace) -> int:
    document = inspect_read_file(args.path, max_bytes=args.max_bytes)
    if args.json:
        print(json.dumps(document, indent=2, sort_keys=True))
        return 0
    print(f"{document['path']}  {document['size_bytes']} bytes  {document['elapsed_ms']} ms")
    print(f"  sha256 {document['sha256']}")
    print(f"  mode {document['mode']}  {'binary' if document['binary'] else 'text'}")
    if document["binary"]:
        print(f"  {document['preview_hex'][:200]}")
    else:
        print(document["preview"][:2000])
    return 0


def cmd_inspect_processes(args: argparse.Namespace) -> int:
    if args.pid is not None:
        print(json.dumps(inspect_process(args.pid), indent=2, sort_keys=True))
        return 0
    document = inspect_processes(limit=args.limit)
    if args.json:
        print(json.dumps(document, indent=2, sort_keys=True))
        return 0
    print(f"{document['count']} processes in {document['elapsed_ms']} ms")
    for item in document["processes"]:
        print(
            f"  {item['pid']:7d} {item['ppid']:7d} {item['state']} "
            f"{item['threads']:3d} {item['rss_bytes'] / 1e6:7.1f} MB  {item['command']}"
        )
    return 0


def cmd_inspect_system(args: argparse.Namespace) -> int:
    document = inspect_snapshot()
    if args.json:
        print(json.dumps(document, indent=2, sort_keys=True))
        return 0
    print(f"{document['hostname']}  kernel {document['kernel']}  {document['elapsed_ms']} ms")
    print(f"  cpu      {document['cpu_count']} x {document['cpu_model'] or 'unknown'}")
    print(f"  load     {document['loadavg']}")
    print(f"  memory   {document['memory']['used_pct']}% of {document['memory']['total_kb']} kB")
    print(f"  disk     {document['disk']['used_pct']}% of {document['disk']['total_bytes']} bytes")
    print(f"  thermal  {document['thermal_c'] or 'no sensors'}")
    print(f"  ports    {len(document['listening_ports'])}")
    print(f"  procs    {document['process_count']}")
    return 0


def cmd_inspect_tree(args: argparse.Namespace) -> int:
    document = inspect_tree(args.path, depth=args.depth, limit=args.limit)
    if args.json:
        print(json.dumps(document, indent=2, sort_keys=True))
        return 0
    print(f"{document['count']} entries in {document['elapsed_ms']} ms")
    for entry in document["entries"]:
        mark = "d" if entry["directory"] else "-"
        print(f"  {mark} {entry['bytes'] if entry['bytes'] is not None else '?':>10}  {entry['path']}")
    return 0


def cmd_stealth_demo(args: argparse.Namespace) -> int:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

    from .stealth import StealthChannel, metrics, onion_peel, onion_route

    channel = StealthChannel(key=b"omnishield-stealth-demo-key-0000", seed=args.seed)
    wire = channel.seal(b"demo payload", cover=args.cover)
    keys = [X25519PrivateKey.generate() for _ in range(args.hops)]
    hops = [
        {
            "address": f"10.0.0.{index + 2}",
            "public": key.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw
            ),
        }
        for index, key in enumerate(keys)
    ]
    private = [
        key.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )
        for key in keys
    ]
    layer = onion_route(hops, b"demo payload", destination=args.destination)
    trace = []
    delivered = None
    for index, key in enumerate(private):
        step = onion_peel(layer, key)
        trace.append({"hop": index + 1, "next": step["next"], "final": step["final"]})
        if step["final"]:
            delivered = step["payload"]
        else:
            layer = json.loads(step["payload"])
    document = {
        "cell_bytes": STEALTH_CELL,
        "wire_cells": len(wire),
        "wire_bytes": len(wire[0]),
        "opened": [payload.decode("utf-8") for payload in channel.open(wire)],
        "metrics": metrics(wire),
        "route": trace,
        "delivered": delivered.decode("utf-8") if delivered is not None else None,
    }
    print(json.dumps(document, indent=2, sort_keys=True))
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    if args.schema:
        print(json.dumps(report_schema(), indent=2, sort_keys=True))
        return 0
    document = build_report(with_doctor=not args.no_doctor)
    text = json.dumps(document, indent=2, sort_keys=True, ensure_ascii=False)
    if args.out:
        Path(args.out).write_text(text + "\n", encoding="utf-8")
    print(text)
    return 0 if document["ok"] else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="omnishield", description=__doc__)
    parser.add_argument("--home", help="state directory (default: ~/.omnishield)")
    parser.add_argument("--backend", default="auto", choices=["auto", "file", "tpm2"])
    parser.add_argument("--name", default="identity", help="key name inside the keystore")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("keygen", help="create a hybrid identity key")
    p.add_argument("--out")
    p.add_argument(
        "--hardware",
        action="store_true",
        help="require a TPM device; refuse instead of pretending",
    )
    p.set_defaults(func=cmd_keygen)

    p = sub.add_parser("sign", help="sign a file")
    p.add_argument("file")
    p.add_argument("--domain", default="file")
    p.add_argument("--out")
    p.set_defaults(func=cmd_sign)

    p = sub.add_parser("verify", help="verify a signed file")
    p.add_argument("file")
    p.add_argument("signature")
    p.add_argument("--domain", default="file")
    p.add_argument("--pub")
    p.add_argument("--replay", action="store_true", help="reject a signature that was already verified")
    p.set_defaults(func=cmd_verify)

    net = sub.add_parser("net", help="protocol 1: network profile and downgrade guard")
    net_sub = net.add_subparsers(dest="net_command", required=True)
    p = net_sub.add_parser("sign", help="sign a network profile")
    p.add_argument("--ssid", required=True)
    p.add_argument("--bssid", action="append")
    p.add_argument("--min-security", default="wpa3-sae")
    p.add_argument("--allow", action="append")
    p.add_argument("--out")
    p.set_defaults(func=cmd_net_sign)
    p = net_sub.add_parser("verify", help="verify a signed network profile")
    p.add_argument("profile")
    p.add_argument("--replay", action="store_true", help="reject a profile that was already consumed")
    p.set_defaults(func=cmd_net_verify)
    p = net_sub.add_parser("enforce", help="emit wpa_supplicant/nmcli enforcement")
    p.add_argument("profile")
    p.add_argument("--interface", default="wlan0")
    p.set_defaults(func=cmd_net_enforce)
    p = net_sub.add_parser("guard", help="negotiate against a peer offer")
    p.add_argument("profile")
    p.add_argument("--offered", nargs="+", required=True)
    p.set_defaults(func=cmd_net_guard)

    ident = sub.add_parser("id", help="protocol 2: hardware-rooted identity")
    id_sub = ident.add_subparsers(dest="id_command", required=True)
    p = id_sub.add_parser("pub", help="print the public identity")
    p.add_argument("--out")
    p.set_defaults(func=cmd_id_pub)
    p = id_sub.add_parser("respond", help="answer a server challenge")
    p.add_argument("--challenge", required=True, help="hex challenge")
    p.add_argument("--context", default="login")
    p.add_argument("--out")
    p.set_defaults(func=cmd_id_respond)
    p = id_sub.add_parser("verify", help="verify a challenge response")
    p.add_argument("response")
    p.add_argument("--pub", required=True)
    p.add_argument("--challenge", required=True)
    p.add_argument("--context")
    p.add_argument("--counters")
    p.set_defaults(func=cmd_id_verify)
    p = id_sub.add_parser("sign-media", help="attach a content credential")
    p.add_argument("file")
    p.add_argument("--capture-origin", default="unknown")
    p.add_argument("--out")
    p.set_defaults(func=cmd_id_sign_media)
    p = id_sub.add_parser("verify-media", help="verify a content credential")
    p.add_argument("file")
    p.add_argument("sidecar")
    p.add_argument("--pub", required=True)
    p.set_defaults(func=cmd_id_verify_media)

    tunnel = sub.add_parser("tunnel", help="protocol 3: ratcheting tunnel")
    tunnel_sub = tunnel.add_subparsers(dest="tunnel_command", required=True)
    p = tunnel_sub.add_parser("demo", help="run a real handshake over a socket pair")
    p.add_argument("--packets", type=int, default=100)
    p.add_argument("--seconds", type=float, default=5.0)
    p.add_argument("--authenticate", action="store_true", help="sign the handshake with the local identity")
    p.set_defaults(func=cmd_tunnel_demo)

    allow = sub.add_parser("allow", help="protocol 4: signed allow-list")
    allow_sub = allow.add_subparsers(dest="allow_command", required=True)
    p = allow_sub.add_parser("build", help="build and sign a manifest")
    p.add_argument("directory")
    p.add_argument("--file", action="append")
    p.add_argument("--out")
    p.set_defaults(func=cmd_allow_build)
    p = allow_sub.add_parser("verify", help="verify a manifest and its artifacts")
    p.add_argument("manifest")
    p.add_argument("--pub", required=True)
    p.add_argument("--no-check-files", action="store_true")
    p.set_defaults(func=cmd_allow_verify)
    p = allow_sub.add_parser("run", help="import a module only if allow-listed")
    p.add_argument("manifest")
    p.add_argument("file")
    p.add_argument("--pub", required=True)
    p.set_defaults(func=cmd_allow_run)

    p = sub.add_parser("guard-demo", help="show the behavioural gate on a bot cadence")
    p.set_defaults(func=cmd_guard_demo)

    org = sub.add_parser("organism", help="Rust organism core (JSON-RPC over stdio)")
    org_sub = org.add_subparsers(dest="organism_command", required=True)
    p = org_sub.add_parser("build", help="compile the Rust core")
    p.add_argument("--debug", action="store_true")
    p.set_defaults(func=cmd_organism_build)
    p = org_sub.add_parser("discover", help="print the method catalog")
    p.add_argument("--binary")
    p.add_argument("--out")
    p.set_defaults(func=cmd_organism_discover)
    p = org_sub.add_parser("call", help="call one JSON-RPC method")
    p.add_argument("method")
    p.add_argument("params", nargs="?", default="{}")
    p.add_argument("--binary")
    p.set_defaults(func=cmd_organism_call)
    p = org_sub.add_parser("state", help="print core state, optionally signed")
    p.add_argument("--binary")
    p.add_argument("--sign", action="store_true")
    p.add_argument("--out")
    p.set_defaults(func=cmd_organism_state)
    p = org_sub.add_parser("verify-state", help="verify a signed state record")
    p.add_argument("file")
    p.add_argument("--pub", required=True)
    p.set_defaults(func=cmd_organism_verify_state)

    features = sub.add_parser("features", help="500-feature ledger with checked evidence")
    features_sub = features.add_subparsers(dest="features_command", required=True)
    p = features_sub.add_parser("audit", help="check every claim against the repository")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_features_audit)
    p = features_sub.add_parser("list", help="list features, optionally filtered")
    p.add_argument("--status", choices=["implemented", "partial", "external", "not_implemented", "undefined", "refused", "duplicate"])
    p.add_argument("--group")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_features_list)
    p = features_sub.add_parser("show", help="show one feature")
    p.add_argument("id", type=int)
    p.set_defaults(func=cmd_features_show)
    memory = sub.add_parser("memory", help="durable memory with a tamper-evident trail")
    memory_sub = memory.add_subparsers(dest="memory_command", required=True)
    p = memory_sub.add_parser("insert", help="store one memory")
    p.add_argument("--db", required=True)
    p.add_argument("--content", required=True)
    p.add_argument("--embedding", required=True, help='e.g. "1,0,0" or "[1,0,0]"')
    p.add_argument("--salience", type=float, default=0.5)
    p.add_argument("--emotion", type=float, default=0.0)
    p.add_argument("--capacity", type=int, default=256)
    p.add_argument("--now-ms", type=int)
    p.set_defaults(func=cmd_memory_insert)
    p = memory_sub.add_parser("search", help="nearest memories by embedding")
    p.add_argument("--db", required=True)
    p.add_argument("--embedding", required=True)
    p.add_argument("--limit", type=int, default=5)
    p.add_argument("--now-ms", type=int)
    p.set_defaults(func=cmd_memory_search)
    p = memory_sub.add_parser("stats", help="live, tombstoned and suppressed counts")
    p.add_argument("--db", required=True)
    p.set_defaults(func=cmd_memory_stats)
    p = memory_sub.add_parser("forget", help="tombstone one memory")
    p.add_argument("--db", required=True)
    p.add_argument("--id", type=int, required=True)
    p.set_defaults(func=cmd_memory_forget)
    p = memory_sub.add_parser("verify", help="check the snapshot against the audit chain")
    p.add_argument("--db", required=True)
    p.set_defaults(func=cmd_memory_verify)
    p = sub.add_parser("status", help="list every component and check its evidence")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_status)

    p = sub.add_parser("doctor", help="run every layer end to end and fail loudly")
    p.add_argument("--json", action="store_true")
    p.add_argument("--jsonl", action="store_true", help="one JSON object per check")
    p.set_defaults(func=cmd_doctor)

    fed = sub.add_parser("federation", help="signed machine-to-machine messaging and device inventory")
    fed_sub = fed.add_subparsers(dest="federation_command", required=True)
    p = fed_sub.add_parser("inventory", help="ARP neighbours and listening TCP ports")
    p.add_argument("--arp", default="/proc/net/arp")
    p.add_argument("--tcp", default="/proc/net/tcp")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_federation_inventory)
    p = fed_sub.add_parser("probe", help="TCP reachability for one host and port")
    p.add_argument("host")
    p.add_argument("--port", type=int, required=True)
    p.add_argument("--timeout", type=float, default=1.0)
    p.set_defaults(func=cmd_federation_probe)
    p = fed_sub.add_parser("beacon", help="print a signed device beacon")
    p.add_argument("--port", type=int, default=0)
    p.add_argument("--capability", action="append", default=[])
    p.add_argument("--ttl", type=int, default=60)
    p.set_defaults(func=cmd_federation_beacon)

    p = sub.add_parser("sovereign", help="Sovereign capability pipeline (hybrid PQ)")
    sovereign_sub = p.add_subparsers(dest="sovereign_command", required=True)
    p = sovereign_sub.add_parser("status", help="show the sovereign-bridge binary and its commands")
    p.set_defaults(func=cmd_sovereign_status)
    p = sovereign_sub.add_parser("pipeline", help="issue and verify a capability end to end")
    p.add_argument("--rights", default="telemetry")
    p.set_defaults(func=cmd_sovereign_pipeline)

    p = sub.add_parser("mlp", help="a two-layer network trained by hand-written backprop")
    mlp_sub = p.add_subparsers(dest="mlp_command", required=True)
    p = mlp_sub.add_parser("demo", help="learn XOR and check the curve in R")
    p.add_argument("--epochs", type=int, default=4000)
    p.set_defaults(func=cmd_mlp_demo)

    p = sub.add_parser("neuron", help="one neuron in Python, checked against Rust and R")
    neuron_sub = p.add_subparsers(dest="neuron_command", required=True)
    p = neuron_sub.add_parser("demo", help="compare dot, forward, training and speed")
    p.add_argument("--dimension", type=int, default=20000)
    p.add_argument("--repeats", type=int, default=10)
    p.set_defaults(func=cmd_neuron_demo)

    p = sub.add_parser("swarm", help="sharded inference over a binary tensor protocol")
    swarm_sub = p.add_subparsers(dest="swarm_command", required=True)
    p = swarm_sub.add_parser("demo", help="two nodes, distributed inference, online learning, guard")
    p.add_argument("--samples", type=int, default=240)
    p.set_defaults(func=cmd_swarm_demo)

    p = sub.add_parser("r", help="export CSV data and analyse it with R")
    r_sub = p.add_subparsers(dest="r_command", required=True)
    p = r_sub.add_parser("export", help="write conversation.csv and answers.csv")
    p.add_argument("--out", default="analysis/data")
    p.add_argument("--conversation", help="JSONL with speaker and text")
    p.add_argument("--questions", help="one question per line")
    p.add_argument("--store")
    p.add_argument("--window", type=int, default=5)
    p.set_defaults(func=cmd_r_export)
    p = r_sub.add_parser("analyse", help="run analysis/conversation.R")
    p.add_argument("--dir", default="analysis/data")
    p.set_defaults(func=cmd_r_analyse)

    p = sub.add_parser("skill", help="list and run named skills")
    skill_sub = p.add_subparsers(dest="skill_command", required=True)
    p = skill_sub.add_parser("list", help="show every skill, its parameters and an example")
    p.set_defaults(func=cmd_skill_list)
    p = skill_sub.add_parser("run", help="run one skill with JSON parameters")
    p.add_argument("--name", required=True)
    p.add_argument("--params", default="{}")
    p.set_defaults(func=cmd_skill_run)

    p = sub.add_parser("omni", help="speak, parse and translate the Omni language")
    omni_sub = p.add_subparsers(dest="omni_command", required=True)
    p = omni_sub.add_parser("say", help="render one sentence in Omni")
    p.add_argument("--subject", required=True)
    p.add_argument("--verb", required=True)
    p.add_argument("--object")
    p.add_argument("--tense", default="present", choices=("present", "past", "future"))
    p.add_argument("--lexicon", default=str(Path.home() / ".omnishield" / "omni.json"))
    p.set_defaults(func=cmd_omni_say)
    p = omni_sub.add_parser("parse", help="read an Omni sentence")
    p.add_argument("--text", required=True)
    p.add_argument("--lexicon", default=str(Path.home() / ".omnishield" / "omni.json"))
    p.set_defaults(func=cmd_omni_parse)
    p = omni_sub.add_parser("translate", help="turn words into Omni roots, learning new ones")
    p.add_argument("--text", required=True)
    p.add_argument("--lexicon", default=str(Path.home() / ".omnishield" / "omni.json"))
    p.set_defaults(func=cmd_omni_translate)

    p = sub.add_parser("think", help="deliberate in steps and show the trace")
    think_sub = p.add_subparsers(dest="think_command", required=True)
    p = think_sub.add_parser("ask", help="retrieve, check for disagreement, then answer")
    p.add_argument("--question", required=True)
    p.add_argument("--depth", type=int, default=4)
    p.add_argument("--store", default=str(Path.home() / ".omnishield" / "knowledge.jsonl"))
    p.set_defaults(func=cmd_think_ask)

    p = sub.add_parser("corpus", help="learn books and dictionaries from files")
    corpus_sub = p.add_subparsers(dest="corpus_command", required=True)
    p = corpus_sub.add_parser("learn", help="ingest one book, one dictionary or a directory")
    p.add_argument("--book")
    p.add_argument("--dictionary")
    p.add_argument("--directory")
    p.add_argument("--store", default=str(Path.home() / ".omnishield" / "knowledge.jsonl"))
    p.add_argument("--lexicon", default=str(Path.home() / ".omnishield" / "omni.json"))
    p.set_defaults(func=cmd_corpus_learn)

    p = sub.add_parser("study", help="teach yourself from stored passages")
    study_sub = p.add_subparsers(dest="study_command", required=True)
    p = study_sub.add_parser("run", help="run lessons over a JSONL file of passages")
    p.add_argument("--file", required=True)
    p.add_argument("--store", default=str(Path.home() / ".omnishield" / "knowledge.jsonl"))
    p.add_argument("--lexicon", default=str(Path.home() / ".omnishield" / "omni.json"))
    p.add_argument("--rounds", type=int, default=1)
    p.set_defaults(func=cmd_study_run)

    p = sub.add_parser("mesh", help="the OmniNet peer protocol")
    net_sub = p.add_subparsers(dest="net_command", required=True)
    p = net_sub.add_parser("keygen", help="generate an Ed25519 key pair")
    p.add_argument("--out", default=str(Path.home() / ".omnishield" / "node-key.json"))
    p.set_defaults(func=cmd_mesh_keygen)
    p = net_sub.add_parser("serve", help="listen for peers for a number of seconds")
    p.add_argument("--id", default="node")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=0)
    p.add_argument("--store", default=str(Path.home() / ".omnishield" / "knowledge.jsonl"))
    p.add_argument("--seconds", type=float, default=10.0)
    p.add_argument("--key")
    p.add_argument("--require-signature", action="store_true")
    p.set_defaults(func=cmd_net_serve)
    p = net_sub.add_parser("chat", help="ask a peer a question over OmniNet")
    p.add_argument("--id", default="node")
    p.add_argument("--peer", required=True)
    p.add_argument("--text", required=True)
    p.add_argument("--key")
    p.add_argument("--store", default=str(Path.home() / ".omnishield" / "knowledge.jsonl"))
    p.set_defaults(func=cmd_mesh_chat)
    p = net_sub.add_parser("gossip", help="send stored items to one peer")
    p.add_argument("--id", default="node")
    p.add_argument("--peer", required=True)
    p.add_argument("--key")
    p.add_argument("--store", default=str(Path.home() / ".omnishield" / "knowledge.jsonl"))
    p.set_defaults(func=cmd_net_gossip)

    p = sub.add_parser("answer", help="extractive answers with BM25, matrices and softmax")
    answer_sub = p.add_subparsers(dest="answer_command", required=True)
    p = answer_sub.add_parser("ask", help="ask the knowledge store a question")
    p.add_argument("--question", required=True)
    p.add_argument("--store", default=str(Path.home() / ".omnishield" / "knowledge.jsonl"))
    p.set_defaults(func=cmd_answer_ask)

    p = sub.add_parser("lang", help="identify languages and follow conversations")
    lang_sub = p.add_subparsers(dest="lang_command", required=True)
    p = lang_sub.add_parser("id", help="identify the language of a line")
    p.add_argument("--text", required=True)
    p.set_defaults(func=cmd_lang_id)
    p = lang_sub.add_parser("follow", help="track a JSONL conversation of speaker and text")
    p.add_argument("--file", required=True)
    p.add_argument("--window", type=int, default=5)
    p.add_argument("--store")
    p.set_defaults(func=cmd_lang_follow)

    p = sub.add_parser("stream", help="fast data transfer and air telemetry")
    stream_sub = p.add_subparsers(dest="stream_command", required=True)
    p = stream_sub.add_parser("bench", help="measure disk write and read throughput")
    p.add_argument("--size-mb", type=int, default=64)
    p.add_argument("--dir")
    p.set_defaults(func=cmd_stream_bench)
    p = stream_sub.add_parser("fetch", help="fetch many urls in parallel and measure MB/s")
    p.add_argument("--urls", required=True)
    p.add_argument("--workers", type=int, default=8)
    p.add_argument("--allow-private", action="store_true")
    p.set_defaults(func=cmd_stream_fetch)
    p = stream_sub.add_parser("telemetry", help="ingest air readings, summarise and alert")
    p.add_argument("--path", required=True)
    p.add_argument("--window", type=int, default=60)
    p.add_argument("--simulate", action="store_true")
    p.add_argument("--minutes", type=int, default=60)
    p.set_defaults(func=cmd_stream_telemetry)

    p = sub.add_parser("speech", help="speak with formants and spot keywords")
    speech_sub = p.add_subparsers(dest="speech_command", required=True)
    p = speech_sub.add_parser("say", help="write text as a WAV")
    p.add_argument("--text", required=True)
    p.add_argument("--speed", type=float, default=1.0)
    p.add_argument("--out", required=True)
    p.set_defaults(func=cmd_speech_say)
    p = speech_sub.add_parser("train", help="add one utterance to a word template")
    p.add_argument("--word", required=True)
    p.add_argument("--wav", required=True)
    p.add_argument("--threshold", type=float, default=40.0)
    p.set_defaults(func=cmd_speech_train)
    p = speech_sub.add_parser("listen", help="spot a keyword in a WAV")
    p.add_argument("--wav", required=True)
    p.add_argument("--words", default="habari,asante")
    p.add_argument("--threshold", type=float, default=60.0)
    p.set_defaults(func=cmd_speech_listen)

    p = sub.add_parser("three", help="3D scenes, orbit animation and simulation")
    three_sub = p.add_subparsers(dest="three_command", required=True)
    p = three_sub.add_parser("scene", help="ray trace the 3D scene")
    p.add_argument("--width", type=int, default=320)
    p.add_argument("--height", type=int, default=200)
    p.add_argument("--samples", type=int, default=2)
    p.add_argument("--engine", default="auto", choices=("auto", "rust", "python"))
    p.add_argument("--threads", type=int, default=4)
    p.add_argument("--angle", type=float, default=0.0)
    p.add_argument("--aperture", type=float, default=0.0)
    p.add_argument("--out", required=True)
    p.set_defaults(func=cmd_three_scene)
    p = three_sub.add_parser("pathtrace", help="render a JSON scene with global illumination")
    p.add_argument("--scene", required=True)
    p.add_argument("--out", required=True)
    p.set_defaults(func=cmd_three_pathtrace)
    p = three_sub.add_parser("video", help="render an orbiting video with the Rust tracer")
    p.add_argument("--frames", type=int, default=24)
    p.add_argument("--preset", default="draft", choices=("draft", "standard", "high"))
    p.add_argument("--aperture", type=float, default=0.02)
    p.add_argument("--out", required=True)
    p.set_defaults(func=cmd_three_video)
    p = three_sub.add_parser("orbit", help="orbit the scene and write a GIF")
    p.add_argument("--frames", type=int, default=12)
    p.add_argument("--width", type=int, default=240)
    p.add_argument("--height", type=int, default=150)
    p.add_argument("--delay", type=int, default=8)
    p.add_argument("--out", required=True)
    p.set_defaults(func=cmd_three_orbit)
    p = three_sub.add_parser("simulate", help="integrate a projectile or a pendulum")
    p.add_argument("--kind", default="projectile", choices=("projectile", "pendulum"))
    p.add_argument("--drag", type=float, default=0.02)
    p.add_argument("--damping", type=float, default=0.0)
    p.set_defaults(func=cmd_three_simulate)
    p = three_sub.add_parser("plot", help="plot 3D points as PNG")
    p.add_argument("--source", default="projectile", choices=("projectile", "points"))
    p.add_argument("--points", default="0:0:0;1:1:1")
    p.add_argument("--title", default="3D")
    p.add_argument("--out", required=True)
    p.set_defaults(func=cmd_three_plot)

    p = sub.add_parser("imagery", help="follow images online and learn from them")
    imagery_sub = p.add_subparsers(dest="imagery_command", required=True)
    p = imagery_sub.add_parser("daily", help="discover, measure and store new images")
    p.add_argument("--feeds", required=True)
    p.add_argument("--out", default="imagery")
    p.add_argument("--state", default=str(Path.home() / ".omnishield"))
    p.add_argument("--limit", type=int, default=8)
    p.add_argument("--allow-private", action="store_true")
    p.set_defaults(func=cmd_imagery_daily)

    p = sub.add_parser("render", help="draw images and animation on the CPU")
    render_sub = p.add_subparsers(dest="render_command", required=True)
    p = render_sub.add_parser("scene", help="render the landscape scene (Rust core when built)")
    p.add_argument("--width", type=int, default=480)
    p.add_argument("--height", type=int, default=300)
    p.add_argument("--samples", type=int, default=2)
    p.add_argument("--engine", default="auto", choices=("auto", "rust", "python"))
    p.add_argument("--out", required=True)
    p.set_defaults(func=cmd_render_scene)
    p = render_sub.add_parser("chart", help="draw a line chart as PNG")
    p.add_argument("--series", required=True)
    p.add_argument("--title", default="Series")
    p.add_argument("--out", required=True)
    p.set_defaults(func=cmd_render_chart)
    p = render_sub.add_parser("art", help="draw procedural art as PNG")
    p.add_argument("--seed", type=int, default=7)
    p.add_argument("--width", type=int, default=480)
    p.add_argument("--height", type=int, default=300)
    p.add_argument("--out", required=True)
    p.set_defaults(func=cmd_render_art)
    p = render_sub.add_parser("video", help="draw an animated GIF")
    p.add_argument("--frames", type=int, default=12)
    p.add_argument("--width", type=int, default=320)
    p.add_argument("--height", type=int, default=200)
    p.add_argument("--seed", type=int, default=3)
    p.add_argument("--delay", type=int, default=8)
    p.add_argument("--out", required=True)
    p.set_defaults(func=cmd_render_video)

    p = sub.add_parser("signal", help="synthesise and clean waveforms")
    signal_sub = p.add_subparsers(dest="signal_command", required=True)
    p = signal_sub.add_parser("synth", help="write a tone as WAV")
    p.add_argument("--freq", default="440")
    p.add_argument("--seconds", type=float, default=1.0)
    p.add_argument("--rate", type=int, default=8000)
    p.add_argument("--out", required=True)
    p.set_defaults(func=cmd_signal_synth)
    p = signal_sub.add_parser("clean", help="clean a WAV and report the stages")
    p.add_argument("--in", dest="input", required=True)
    p.add_argument("--out", required=True)
    p.set_defaults(func=cmd_signal_clean)

    p = sub.add_parser("worship", help="the daily office of prayer and song")
    worship_sub = p.add_subparsers(dest="worship_command", required=True)
    p = worship_sub.add_parser("daily", help="write today's office, hymn and verse card")
    p.add_argument("--out", default="worship")
    p.add_argument("--journal")
    p.add_argument("--day", type=int)
    p.add_argument("--notify", help="recipient file; sends a dry run unless --send is given")
    p.add_argument("--send", action="store_true")
    p.set_defaults(func=cmd_worship_daily)
    p = worship_sub.add_parser("sing", help="write one hymn as WAV")
    p.add_argument("--theme", default="shukrani", choices=("shukrani", "nuru", "huruma", "imani", "matumaini", "amani", "upendo", "hekima"))
    p.add_argument("--rate", type=int, default=8000)
    p.add_argument("--out", required=True)
    p.set_defaults(func=cmd_worship_sing)
    p = worship_sub.add_parser("journal", help="show the practice journal")
    p.add_argument("--journal")
    p.set_defaults(func=cmd_worship_journal)

    p = sub.add_parser("notify", help="consent-based notifications")
    notify_sub = p.add_subparsers(dest="notify_command", required=True)
    p = notify_sub.add_parser("test", help="send a dry run to the recipient file")
    p.add_argument("--to", required=True)
    p.add_argument("--state")
    p.add_argument("--send", action="store_true")
    p.set_defaults(func=cmd_notify_test)

    p = sub.add_parser("thermal", help="measure CPU usage and temperature")
    thermal_sub = p.add_subparsers(dest="thermal_command", required=True)
    p = thermal_sub.add_parser("status", help="show usage, temperature and duty cycle")
    p.add_argument("--target", type=float, default=0.7)
    p.set_defaults(func=cmd_thermal_status)

    p = sub.add_parser("doc", help="write DOCX, XLSX, PPTX and PDF reports")
    doc_sub = p.add_subparsers(dest="doc_command", required=True)
    p = doc_sub.add_parser("report", help="write the measured status report in every format")
    p.add_argument("--out", default="analysis/out")
    p.set_defaults(func=cmd_doc_report)

    p = sub.add_parser("predict", help="forecast a reading, then check it against reality")
    predict_sub = p.add_subparsers(dest="predict_command", required=True)
    p = predict_sub.add_parser("system", help="predict load and memory, then measure them")
    p.add_argument("--samples", type=int, default=6)
    p.add_argument("--interval", type=float, default=0.0)
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_predict_system)

    p = sub.add_parser("learn", help="daily knowledge loop over feeds and pages")
    learn_sub = p.add_subparsers(dest="learn_command", required=True)
    p = learn_sub.add_parser("add", help="store one piece of text")
    p.add_argument("text")
    p.add_argument("--source", default="manual")
    p.add_argument("--title")
    p.add_argument("--tag", action="append")
    p.add_argument("--state")
    p.set_defaults(func=cmd_learn_add)
    p = learn_sub.add_parser("page", help="fetch one page and store its text")
    p.add_argument("url")
    p.add_argument("--allow-private", action="store_true")
    p.add_argument("--tag", action="append")
    p.add_argument("--state")
    p.set_defaults(func=cmd_learn_page)
    p = learn_sub.add_parser("feed", help="fetch an RSS or Atom feed")
    p.add_argument("url")
    p.add_argument("--limit", type=int, default=20)
    p.add_argument("--allow-private", action="store_true")
    p.add_argument("--tag", action="append")
    p.add_argument("--state")
    p.set_defaults(func=cmd_learn_feed)
    p = learn_sub.add_parser("search", help="search what has been learned")
    p.add_argument("query")
    p.add_argument("--limit", type=int, default=10)
    p.add_argument("--json", action="store_true")
    p.add_argument("--state")
    p.set_defaults(func=cmd_learn_search)
    p = learn_sub.add_parser("stats", help="store size, tags and curiosity gaps")
    p.add_argument("--state")
    p.set_defaults(func=cmd_learn_stats)
    p = learn_sub.add_parser("cycle", help="read every feed in a file, then consolidate")
    p.add_argument("--feeds", required=True)
    p.add_argument("--limit", type=int, default=20)
    p.add_argument("--allow-private", action="store_true")
    p.add_argument("--tag", action="append")
    p.add_argument("--state")
    p.set_defaults(func=cmd_learn_cycle)
    p = learn_sub.add_parser("review", help="what is due for spaced repetition")
    p.add_argument("--limit", type=int, default=10)
    p.add_argument("--state")
    p.set_defaults(func=cmd_learn_review)
    p = learn_sub.add_parser("grade", help="record a recall grade from 0 to 5")
    p.add_argument("id")
    p.add_argument("grade", type=int)
    p.add_argument("--state")
    p.set_defaults(func=cmd_learn_grade)

    p = sub.add_parser("inspect", help="read any file and list every process, timed")
    inspect_sub = p.add_subparsers(dest="inspect_command", required=True)
    p = inspect_sub.add_parser("file", help="size, hash, kind and a bounded preview")
    p.add_argument("path")
    p.add_argument("--max-bytes", type=int, default=1_000_000)
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_inspect_file)
    p = inspect_sub.add_parser("processes", help="every process, one pass over /proc")
    p.add_argument("--limit", type=int)
    p.add_argument("--pid", type=int)
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_inspect_processes)
    p = inspect_sub.add_parser("system", help="host, cpu, memory, disk, thermal, ports")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_inspect_system)
    p = inspect_sub.add_parser("tree", help="bounded directory walk")
    p.add_argument("path")
    p.add_argument("--depth", type=int, default=2)
    p.add_argument("--limit", type=int, default=200)
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_inspect_tree)

    p = sub.add_parser("stealth", help="fixed-size cells, cover traffic and onion relay")
    stealth_sub = p.add_subparsers(dest="stealth_command", required=True)
    p = stealth_sub.add_parser("demo", help="seal cells, add cover and peel a route")
    p.add_argument("--hops", type=int, default=3)
    p.add_argument("--cover", type=int, default=3)
    p.add_argument("--seed", type=int, default=7)
    p.add_argument("--destination", default=None)
    p.set_defaults(func=cmd_stealth_demo)

    p = sub.add_parser("report", help="one JSON document for CI and other agents")
    p.add_argument("--no-doctor", action="store_true", help="skip the end-to-end checks")
    p.add_argument("--out", help="also write the document to this path")
    p.add_argument("--schema", action="store_true", help="print the JSON schema instead")
    p.set_defaults(func=cmd_report)

    p = sub.add_parser("export", help="write tidy CSV for analysis and reporting")
    p.add_argument("--out", required=True, help="directory for the CSV files")
    p.add_argument("--memory", help="memory database to export")
    p.add_argument("--payments", help="payment ledger (JSONL) to export")
    p.add_argument("--audit", help="audit log (JSONL) to export")
    p.set_defaults(func=cmd_export)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except (
        SigError,
        KeyStoreError,
        OrganismError,
        CatalogError,
        MemoryStoreError,
        DeviceError,
        OSError,
        ValueError,
    ) as exc:
        print(f"rejected: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
