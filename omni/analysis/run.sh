#!/usr/bin/env bash
# Export live state, analyse it in R, and render the report.
#
#   analysis/run.sh                 # current repository state
#   analysis/run.sh --demo          # a small synthetic state, to see the full report
#   analysis/run.sh live  data out  # explicit directories
set -euo pipefail

MODE="${1:-live}"
DATA_DIR="${2:-analysis/data}"
OUT_DIR="${3:-analysis/out}"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if ! command -v Rscript >/dev/null 2>&1; then
  echo "Rscript not found: install R (e.g. apt-get install r-base-core)" >&2
  exit 2
fi

ARGS=()
if [[ "$MODE" == "--demo" ]]; then
  STATE="$(mktemp -d)"
  trap 'rm -rf "$STATE"' EXIT
  python3 - "$STATE" <<'PY'
import sys
from pathlib import Path

from omnishield.audit import AuditLog
from omnishield.hybrid import HybridSigner
from omnishield.memory_store import PersistentMemory
from omnishield.payments import PaymentService

state = Path(sys.argv[1])
audit = AuditLog(state / "audit.log", key=b"omnishield-demo-audit-key-32byte")
memory = PersistentMemory(state / "memory.db")
for text, vector, salience in (
    ("mkutano wa bodi", "1,0,0", 0.9),
    ("barua ya benki", "0,1,0", 0.6),
    ("ripoti ya mwezi", "0.7,0.7,0", 0.4),
):
    memory.insert(text, vector, salience=salience)
audit.append("demo.memory", {"inserted": 3})


class Gateway:
    def charge(self, intent):
        return f"demo-{intent['intent_id'][:6]}"


requester = HybridSigner.generate()
approver = HybridSigner.generate()
payments = PaymentService(state / "payments.jsonl", requester, gateway=Gateway())
for amount, currency, payee in ((12500, "TZS", "Amina"), (8000, "TZS", "Juma"), (2500, "KES", "Amina")):
    intent = payments.create(amount, currency, payee)
    approval = payments.approve(intent, approver, approver_name="human:amina")
    payments.settle(intent, approval, approver.public_identity)
    audit.append("demo.payment", {"payee": payee, "amount_cents": amount})
PY
  ARGS=(--memory "$STATE/memory.db" --payments "$STATE/payments.jsonl" --audit "$STATE/audit.log")
fi

python3 -m omnishield export --out "$DATA_DIR" ${ARGS[@]+"${ARGS[@]}"} >/dev/null
Rscript analysis/analyse.R "$DATA_DIR" "$OUT_DIR"
Rscript analysis/report.R "$DATA_DIR" "$OUT_DIR"
echo "report: $OUT_DIR/REPORT.md"
