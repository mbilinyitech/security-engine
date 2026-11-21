import shutil
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
RSCRIPT = shutil.which("Rscript")

pytestmark = pytest.mark.skipif(
    RSCRIPT is None, reason="R is not installed (apt-get install r-base-core)"
)


def test_demo_pipeline_produces_markdown_html_and_charts(tmp_path):
    data = tmp_path / "data"
    out = tmp_path / "out"
    result = subprocess.run(
        ["bash", str(REPO / "analysis" / "run.sh"), "--demo", str(data), str(out)],
        cwd=REPO,
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )
    assert result.returncode == 0, result.stderr[-800:]

    report = (out / "REPORT.md").read_text(encoding="utf-8")
    for section in (
        "# OmniShield analysis report",
        "## Headline",
        "## Feature coverage",
        "## Components",
        "## Doctor checks",
        "## Memory",
        "## Payments",
        "## Audit activity",
        "## Provenance",
    ):
        assert section in report
    assert "| Features in the ledger | 500 |" in report
    assert "| Doctor checks passed | 64 / 64 |" in report

    html = (out / "report.html").read_text(encoding="utf-8")
    assert "<table>" in html
    assert '<img src="status.png"' in html

    for chart in (
        "status.png",
        "coverage_by_group.png",
        "doctor_ms.png",
        "memory_salience.png",
        "payments_by_payee.png",
        "audit_kinds.png",
    ):
        assert (out / chart).stat().st_size > 1000, chart
