import zipfile
from xml.etree import ElementTree

import pytest

from omnishield.docgen import (
    DocError,
    docx,
    markdown,
    pdf,
    pptx,
    report,
    xlsx,
)
from omnishield.render import chart

BLOCKS = [
    {"type": "h1", "text": "Quarterly Review"},
    {"type": "p", "text": "Everything below comes from a measured run."},
    {"type": "h2", "text": "Findings"},
    {"type": "bullet", "text": "Coverage reached 77.8 percent."},
    {"type": "table", "rows": [["Metric", "Value"], ["Tests", "394"], ["Doctor", "34/34"]]},
    {"type": "quote", "text": "Measure, then claim."},
    {"type": "code", "text": "omnishield report --out out"},
]


def _parts(payload: bytes) -> dict[str, bytes]:
    from io import BytesIO

    with zipfile.ZipFile(BytesIO(payload)) as archive:
        return {name: archive.read(name) for name in archive.namelist()}


def test_docx_is_a_real_word_package():
    payload = docx(BLOCKS, title="Quarterly Review")
    parts = _parts(payload)
    assert "word/document.xml" in parts
    assert "word/styles.xml" in parts
    assert "[Content_Types].xml" in parts
    document = ElementTree.fromstring(parts["word/document.xml"])
    text = "".join(node.text or "" for node in document.iter())
    assert "Quarterly Review" in text
    assert "Coverage reached" in text
    assert "Metric" in text
    assert document.tag.endswith("document")
    with pytest.raises(DocError):
        docx([], title="x")


def test_xlsx_has_sheets_cells_and_a_header_style():
    payload = xlsx(
        {"Coverage": [["Group", "Built"], ["Memory", 20], ["Learning", 15]]},
        title="Workbook",
    )
    parts = _parts(payload)
    assert "xl/workbook.xml" in parts
    assert "xl/styles.xml" in parts
    workbook = ElementTree.fromstring(parts["xl/workbook.xml"])
    names = [node.get("name") for node in workbook.iter() if node.tag.endswith("sheet")]
    assert names == ["Coverage"]
    sheet = parts["xl/worksheets/sheet1.xml"].decode()
    assert 'r="A1"' in sheet and 's="1"' in sheet
    assert "Memory" in sheet
    assert "<v>20</v>" in sheet
    assert "pane" in sheet
    with pytest.raises(DocError):
        xlsx({}, title="x")


def test_pptx_has_slides_master_layout_and_theme():
    payload = pptx(
        [
            {"title": "OmniShield", "lines": ["Built from measurements"], "dark": True},
            {"title": "Numbers", "lines": ["389 built", "34/34 doctor"]},
        ],
        title="Deck",
    )
    parts = _parts(payload)
    assert "ppt/presentation.xml" in parts
    assert "ppt/slideMasters/slideMaster1.xml" in parts
    assert "ppt/slideLayouts/slideLayout1.xml" in parts
    assert "ppt/theme/theme1.xml" in parts
    presentation = ElementTree.fromstring(parts["ppt/presentation.xml"])
    slide_ids = [node for node in presentation.iter() if node.tag.endswith("sldId")]
    assert len(slide_ids) == 2
    slide = ElementTree.fromstring(parts["ppt/slides/slide2.xml"])
    text = "".join(node.text or "" for node in slide.iter())
    assert "Numbers" in text and "389 built" in text
    with pytest.raises(DocError):
        pptx([], title="x")


def test_pdf_has_pages_text_and_a_trailer(tmp_path):
    image = chart([1, 3, 2, 5], title="Chart")
    image.save_png(tmp_path / "chart.png")
    payload = pdf(
        [*BLOCKS, {"type": "image", "path": str(tmp_path / "chart.png")}, {"type": "pagebreak"}, {"type": "h2", "text": "Method"}],
        title="Quarterly Review",
    )
    assert payload.startswith(b"%PDF-1.4")
    assert payload.rstrip().endswith(b"%%EOF")
    assert payload.count(b"/Type /Page ") == 2
    assert b"/Subtype /Image" in payload
    assert b"Quarterly Review" in payload
    assert b"/Title (Quarterly Review)" in payload
    with pytest.raises(DocError):
        pdf([], title="x")


def test_report_writes_every_format(tmp_path):
    written = report(
        "Measured Report",
        BLOCKS,
        out_dir=tmp_path,
        sheets={"Coverage": [["Group", "Built"], ["Memory", 20]]},
        slides=[{"title": "Measured Report", "lines": ["389 built"]}],
    )
    assert set(written) == {"markdown", "docx", "pdf", "xlsx", "pptx"}
    for entry in written.values():
        assert entry["bytes"] > 0
    text = (tmp_path / "measured-report.md").read_text(encoding="utf-8")
    assert "# Quarterly Review" in text
    assert "| Metric | Value |" in text
    assert "omnishield report --out out" in text


def test_markdown_renders_every_block_type():
    text = markdown(
        [
            {"type": "h1", "text": "A"},
            {"type": "h3", "text": "B"},
            {"type": "quote", "text": "C"},
            {"type": "image", "path": "/tmp/x.png"},
            {"type": "pagebreak"},
        ]
    )
    assert "# A" in text and "### B" in text and "> C" in text
    assert "![chart](x.png)" in text
    assert "---" in text
