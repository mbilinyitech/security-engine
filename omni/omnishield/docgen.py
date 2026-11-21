"""Write real Office files and PDFs, then a report that uses all of them.

DOCX, XLSX and PPTX are OOXML zip packages written by hand: no template, no
office suite, no external dependency. PDF 1.4 is written object by object with
the standard fonts. Every file is verified by the tests, which unzip the package
and parse the XML or count the PDF pages.
"""

from __future__ import annotations

import time
import zipfile
from collections.abc import Mapping, Sequence
from io import BytesIO
from pathlib import Path
from typing import Any
from xml.sax.saxutils import escape

from .vision import decode_png

NS = 'xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"'
CONTENT_TYPES = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
<Default Extension="xml" ContentType="application/xml"/>
{overrides}
</Types>"""
ROOT_RELS = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="{target}"/>
</Relationships>"""


class DocError(Exception):
    pass


def _zip(parts: Mapping[str, bytes]) -> bytes:
    buffer = BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, payload in parts.items():
            info = zipfile.ZipInfo(name, date_time=(2024, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, payload)
    return buffer.getvalue()


def _overrides(entries: Mapping[str, str]) -> str:
    return "\n".join(
        f'<Override PartName="/{name}" ContentType="{kind}"/>' for name, kind in entries.items()
    )


def _paragraph(text: str, style: str | None = None, *, bold: bool = False) -> str:
    properties = f'<w:pPr><w:pStyle w:val="{style}"/></w:pPr>' if style else ""
    run_properties = "<w:rPr><w:b/></w:rPr>" if bold else ""
    return f"<w:p>{properties}<w:r>{run_properties}<w:t xml:space=\"preserve\">{escape(text)}</w:t></w:r></w:p>"


def _table(rows: Sequence[Sequence[str]]) -> str:
    if not rows:
        return ""
    cells = []
    for index, row in enumerate(rows):
        cells.append("<w:tr>")
        for cell in row:
            cells.append(
                '<w:tc><w:tcPr><w:tcBorders>'
                '<w:top w:val="single" w:sz="4" w:color="CBD5E1"/>'
                '<w:bottom w:val="single" w:sz="4" w:color="CBD5E1"/>'
                '<w:left w:val="single" w:sz="4" w:color="CBD5E1"/>'
                '<w:right w:val="single" w:sz="4" w:color="CBD5E1"/>'
                "</w:tcBorders></w:tcPr>"
                + _paragraph(str(cell), bold=index == 0)
                + "</w:tc>"
            )
        cells.append("</w:tr>")
    return (
        "<w:tbl><w:tblPr><w:tblW w:w=\"0\" w:type=\"auto\"/></w:tblPr>"
        + "".join(cells)
        + "</w:tbl>"
    )


def _blocks_to_docx(blocks: Sequence[Mapping[str, Any]]) -> str:
    body = []
    for block in blocks:
        kind = block.get("type", "p")
        if kind == "h1":
            body.append(_paragraph(str(block["text"]), "Title"))
        elif kind == "h2":
            body.append(_paragraph(str(block["text"]), "Heading1"))
        elif kind == "h3":
            body.append(_paragraph(str(block["text"]), "Heading2"))
        elif kind == "bullet":
            body.append(_paragraph(f"\u2022 {block['text']}", "ListBullet"))
        elif kind == "quote":
            body.append(_paragraph(str(block["text"]), "Quote"))
        elif kind == "code":
            body.append(_paragraph(str(block["text"]), "Code"))
        elif kind == "table":
            body.append(_table(block["rows"]))
            body.append(_paragraph(""))
        elif kind == "pagebreak":
            body.append('<w:p><w:r><w:br w:type="page"/></w:r></w:p>')
        else:
            body.append(_paragraph(str(block.get("text", ""))))
    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        f"<w:document {NS}><w:body>{''.join(body)}"
        '<w:sectPr><w:pgSz w:w="11906" w:h="16838"/>'
        '<w:pgMar w:top="1440" w:right="1440" w:bottom="1440" w:left="1440"/></w:sectPr>'
        "</w:body></w:document>"
    )


DOCX_STYLES = f"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:styles {NS}>
<w:docDefaults><w:rPrDefault><w:rPr>
<w:rFonts w:ascii="Calibri" w:hAnsi="Calibri"/><w:sz w:val="22"/>
</w:rPr></w:rPrDefault></w:docDefaults>
<w:style w:type="paragraph" w:default="1" w:styleId="Normal"><w:name w:val="Normal"/></w:style>
<w:style w:type="paragraph" w:styleId="Title"><w:name w:val="Title"/>
<w:basedOn w:val="Normal"/><w:pPr><w:spacing w:before="240" w:after="240"/></w:pPr>
<w:rPr><w:b/><w:sz w:val="56"/><w:color w:val="0F172A"/></w:rPr></w:style>
<w:style w:type="paragraph" w:styleId="Heading1"><w:name w:val="heading 1"/>
<w:basedOn w:val="Normal"/><w:pPr><w:spacing w:before="360" w:after="120"/></w:pPr>
<w:rPr><w:b/><w:sz w:val="34"/><w:color w:val="1D4ED8"/></w:rPr></w:style>
<w:style w:type="paragraph" w:styleId="Heading2"><w:name w:val="heading 2"/>
<w:basedOn w:val="Normal"/><w:pPr><w:spacing w:before="240" w:after="80"/></w:pPr>
<w:rPr><w:b/><w:sz w:val="27"/><w:color w:val="334155"/></w:rPr></w:style>
<w:style w:type="paragraph" w:styleId="ListBullet"><w:name w:val="List Bullet"/>
<w:basedOn w:val="Normal"/><w:pPr><w:ind w:left="360"/></w:pPr></w:style>
<w:style w:type="paragraph" w:styleId="Quote"><w:name w:val="Quote"/>
<w:basedOn w:val="Normal"/><w:rPr><w:i/><w:color w:val="475569"/></w:rPr></w:style>
<w:style w:type="paragraph" w:styleId="Code"><w:name w:val="Code"/>
<w:basedOn w:val="Normal"/><w:rPr><w:rFonts w:ascii="Consolas" w:hAnsi="Consolas"/>
<w:sz w:val="19"/></w:rPr></w:style>
</w:styles>"""


def _core(title: str, author: str) -> bytes:
    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" '
        'xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/" '
        'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">'
        f"<dc:title>{escape(title)}</dc:title><dc:creator>{escape(author)}</dc:creator>"
        f"<cp:lastModifiedBy>{escape(author)}</cp:lastModifiedBy>"
        f'<dcterms:created xsi:type="dcterms:W3CDTF">{now}</dcterms:created>'
        "</cp:coreProperties>"
    ).encode()


def docx(blocks: Sequence[Mapping[str, Any]], *, title: str, author: str = "OmniShield") -> bytes:
    if not blocks:
        raise DocError("a document needs at least one block")
    parts = {
        "[Content_Types].xml": CONTENT_TYPES.format(
            overrides=_overrides(
                {
                    "word/document.xml": "application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml",
                    "word/styles.xml": "application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml",
                    "docProps/core.xml": "application/vnd.openxmlformats-package.core-properties+xml",
                }
            )
        ).encode(),
        "_rels/.rels": ROOT_RELS.format(target="word/document.xml").encode(),
        "word/document.xml": _blocks_to_docx(blocks).encode(),
        "word/styles.xml": DOCX_STYLES.encode(),
        "docProps/core.xml": _core(title, author),
    }
    return _zip(parts)


XLSX_STYLES = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
<fonts count="3"><font><sz val="11"/><name val="Calibri"/></font>
<font><b/><sz val="11"/><name val="Calibri"/></font>
<font><b/><sz val="11"/><color rgb="FFFFFFFF"/><name val="Calibri"/></font></fonts>
<fills count="3"><fill><patternFill patternType="none"/></fill>
<fill><patternFill patternType="gray125"/></fill>
<fill><patternFill patternType="solid"><fgColor rgb="FF1D4ED8"/><bgColor indexed="64"/></patternFill></fill></fills>
<borders count="1"><border><left/><right/><top/><bottom/><diagonal/></border></borders>
<cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>
<cellXfs count="3"><xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/>
<xf numFmtId="0" fontId="2" fillId="2" borderId="0" xfId="0" applyFont="1" applyFill="1"/>
<xf numFmtId="2" fontId="0" fillId="0" borderId="0" xfId="0" applyNumberFormat="1"/></cellXfs>
</styleSheet>"""


def _column(index: int) -> str:
    letters = ""
    index += 1
    while index:
        index, remainder = divmod(index - 1, 26)
        letters = chr(65 + remainder) + letters
    return letters


def _sheet_xml(rows: Sequence[Sequence[Any]], widths: Sequence[int] | None = None) -> str:
    columns = ""
    if widths:
        columns = "<cols>" + "".join(
            f'<col min="{index + 1}" max="{index + 1}" width="{width}" customWidth="1"/>'
            for index, width in enumerate(widths)
        ) + "</cols>"
    body = []
    for row_index, row in enumerate(rows):
        cells = []
        for column_index, value in enumerate(row):
            reference = f"{_column(column_index)}{row_index + 1}"
            style = ' s="1"' if row_index == 0 else ""
            if isinstance(value, (int, float)) and not isinstance(value, bool):
                cells.append(f'<c r="{reference}"{style}><v>{value}</v></c>')
            else:
                cells.append(
                    f'<c r="{reference}"{style} t="inlineStr"><is><t xml:space="preserve">'
                    f"{escape(str(value))}</t></is></c>"
                )
        body.append(f'<row r="{row_index + 1}">' + "".join(cells) + "</row>")
    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
        '<sheetViews><sheetView workbookViewId="0">'
        '<pane ySplit="1" topLeftCell="A2" activePane="bottomLeft" state="frozen"/>'
        "</sheetView></sheetViews>"
        f"{columns}<sheetData>{''.join(body)}</sheetData></worksheet>"
    )


def xlsx(
    sheets: Mapping[str, Sequence[Sequence[Any]]], *, title: str, author: str = "OmniShield"
) -> bytes:
    if not sheets:
        raise DocError("a workbook needs at least one sheet")
    names = list(sheets)
    parts: dict[str, bytes] = {}
    overrides = {
        "xl/workbook.xml": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml",
        "xl/styles.xml": "application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml",
    }
    entries = []
    for index, name in enumerate(names, start=1):
        parts[f"xl/worksheets/sheet{index}.xml"] = _sheet_xml(sheets[name]).encode()
        overrides[f"xl/worksheets/sheet{index}.xml"] = (
            "application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"
        )
        entries.append(
            f'<Relationship Id="rId{index}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet{index}.xml"/>'
        )
    entries.append(
        f'<Relationship Id="rId{len(names) + 1}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>'
    )
    parts["[Content_Types].xml"] = CONTENT_TYPES.format(overrides=_overrides(overrides)).encode()
    parts["_rels/.rels"] = ROOT_RELS.format(target="xl/workbook.xml").encode()
    parts["xl/workbook.xml"] = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
        'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets>'
        + "".join(
            f'<sheet name="{escape(name)}" sheetId="{index}" r:id="rId{index}"/>'
            for index, name in enumerate(names, start=1)
        )
        + "</sheets></workbook>"
    ).encode()
    parts["xl/_rels/workbook.xml.rels"] = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        + "".join(entries)
        + "</Relationships>"
    ).encode()
    parts["xl/styles.xml"] = XLSX_STYLES.encode()
    parts["docProps/core.xml"] = _core(title, author)
    overrides["docProps/core.xml"] = "application/vnd.openxmlformats-package.core-properties+xml"
    parts["[Content_Types].xml"] = CONTENT_TYPES.format(overrides=_overrides(overrides)).encode()
    return _zip(parts)


THEME = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<a:theme xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" name="OmniShield">
<a:themeElements><a:clrScheme name="OmniShield">
<a:dk1><a:srgbClr val="0F172A"/></a:dk1><a:lt1><a:srgbClr val="FFFFFF"/></a:lt1>
<a:dk2><a:srgbClr val="1E293B"/></a:dk2><a:lt2><a:srgbClr val="F1F5F9"/></a:lt2>
<a:accent1><a:srgbClr val="1D4ED8"/></a:accent1><a:accent2><a:srgbClr val="0EA5E9"/></a:accent2>
<a:accent3><a:srgbClr val="10B981"/></a:accent3><a:accent4><a:srgbClr val="F59E0B"/></a:accent4>
<a:accent5><a:srgbClr val="EF4444"/></a:accent5><a:accent6><a:srgbClr val="8B5CF6"/></a:accent6>
<a:hlink><a:srgbClr val="1D4ED8"/></a:hlink><a:folHlink><a:srgbClr val="7C3AED"/></a:folHlink>
</a:clrScheme>
<a:fontScheme name="OmniShield"><a:majorFont><a:latin typeface="Calibri Light"/></a:majorFont>
<a:minorFont><a:latin typeface="Calibri"/></a:minorFont></a:fontScheme>
<a:fmtScheme name="OmniShield"><a:fillStyleLst><a:solidFill><a:schemeClr val="phClr"/></a:solidFill>
<a:solidFill><a:schemeClr val="phClr"/></a:solidFill><a:solidFill><a:schemeClr val="phClr"/></a:solidFill></a:fillStyleLst>
<a:lnStyleLst><a:ln w="6350"><a:solidFill><a:schemeClr val="phClr"/></a:solidFill></a:ln>
<a:ln w="12700"><a:solidFill><a:schemeClr val="phClr"/></a:solidFill></a:ln>
<a:ln w="19050"><a:solidFill><a:schemeClr val="phClr"/></a:solidFill></a:ln></a:lnStyleLst>
<a:effectStyleLst><a:effectStyle><a:effectLst/></a:effectStyle><a:effectStyle><a:effectLst/></a:effectStyle>
<a:effectStyle><a:effectLst/></a:effectStyle></a:effectStyleLst>
<a:bgFillStyleLst><a:solidFill><a:schemeClr val="phClr"/></a:solidFill>
<a:solidFill><a:schemeClr val="phClr"/></a:solidFill><a:solidFill><a:schemeClr val="phClr"/></a:solidFill></a:bgFillStyleLst>
</a:fmtScheme></a:themeElements></a:theme>"""

SLIDE_MASTER = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<p:sldMaster xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main">
<p:cSld><p:spTree><p:nvGrpSpPr><p:cNvPr id="1" name=""/><p:cNvGrpSpPr/><p:nvPr/></p:nvGrpSpPr>
<p:grpSpPr><a:xfrm><a:off x="0" y="0"/><a:ext cx="0" cy="0"/><a:chOff x="0" y="0"/><a:chExt cx="0" cy="0"/></a:xfrm></p:grpSpPr>
</p:spTree></p:cSld><p:clrMap bg1="lt1" tx1="dk1" bg2="lt2" tx2="dk2" accent1="accent1" accent2="accent2" accent3="accent3" accent4="accent4" accent5="accent5" accent6="accent6" hlink="hlink" folHlink="folHlink"/>
<p:sldLayoutIdLst><p:sldLayoutId id="2147483649" r:id="rId1"/></p:sldLayoutIdLst></p:sldMaster>"""

SLIDE_LAYOUT = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<p:sldLayout xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main" type="blank">
<p:cSld name="Blank"><p:spTree><p:nvGrpSpPr><p:cNvPr id="1" name=""/><p:cNvGrpSpPr/><p:nvPr/></p:nvGrpSpPr>
<p:grpSpPr><a:xfrm><a:off x="0" y="0"/><a:ext cx="0" cy="0"/><a:chOff x="0" y="0"/><a:chExt cx="0" cy="0"/></a:xfrm></p:grpSpPr>
</p:spTree></p:cSld></p:sldLayout>"""


def _slide(title: str, lines: Sequence[str], *, number: int, dark: bool = False) -> str:
    background = "0F172A" if dark else "FFFFFF"
    title_color = "FFFFFF" if dark else "0F172A"
    body_color = "E2E8F0" if dark else "334155"
    body = "".join(
        f'<a:p><a:r><a:rPr lang="en-US" sz="2000"><a:solidFill><a:srgbClr val="{body_color}"/></a:solidFill></a:rPr>'
        f"<a:t>{escape(line)}</a:t></a:r></a:p>"
        for line in lines
    )
    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<p:sld xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" '
        'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" '
        'xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main"><p:cSld>'
        "<p:bg><p:bgPr><a:solidFill>"
        f'<a:srgbClr val="{background}"/>'
        "</a:solidFill><a:effectLst/></p:bgPr></p:bg>"
        '<p:spTree><p:nvGrpSpPr><p:cNvPr id="1" name=""/><p:cNvGrpSpPr/><p:nvPr/></p:nvGrpSpPr>'
        '<p:grpSpPr><a:xfrm><a:off x="0" y="0"/><a:ext cx="0" cy="0"/><a:chOff x="0" y="0"/>'
        '<a:chExt cx="0" cy="0"/></a:xfrm></p:grpSpPr>'
        '<p:sp><p:nvSpPr><p:cNvPr id="2" name="Title"/><p:cNvSpPr><a:spLocks noGrp="1"/></p:cNvSpPr>'
        "<p:nvPr/></p:nvSpPr>"
        '<p:spPr><a:xfrm><a:off x="838200" y="457200"/><a:ext cx="10515600" cy="1325563"/></a:xfrm>'
        '<a:prstGeom prst="rect"><a:avLst/></a:prstGeom></p:spPr>'
        '<p:txBody><a:bodyPr/><a:lstStyle/><a:p><a:r><a:rPr lang=\"en-US\" sz=\"4000\" b=\"1\">'
        f'<a:solidFill><a:srgbClr val="{title_color}"/></a:solidFill></a:rPr>'
        f"<a:t>{escape(title)}</a:t></a:r></a:p></p:txBody></p:sp>"
        '<p:sp><p:nvSpPr><p:cNvPr id="3" name="Body"/><p:cNvSpPr><a:spLocks noGrp="1"/></p:cNvSpPr>'
        "<p:nvPr/></p:nvSpPr>"
        '<p:spPr><a:xfrm><a:off x="838200" y="1828800"/><a:ext cx="10515600" cy="4114800"/></a:xfrm>'
        '<a:prstGeom prst="rect"><a:avLst/></a:prstGeom></p:spPr>'
        f"<p:txBody><a:bodyPr/><a:lstStyle/>{body}</p:txBody></p:sp>"
        '<p:sp><p:nvSpPr><p:cNvPr id="4" name="Footer"/><p:cNvSpPr><a:spLocks noGrp="1"/></p:cNvSpPr>'
        "<p:nvPr/></p:nvSpPr>"
        '<p:spPr><a:xfrm><a:off x="838200" y="6400800"/><a:ext cx="10515600" cy="365760"/></a:xfrm>'
        '<a:prstGeom prst="rect"><a:avLst/></a:prstGeom></p:spPr>'
        '<p:txBody><a:bodyPr/><a:lstStyle/><a:p><a:r><a:rPr lang="en-US" sz="1100">'
        f'<a:solidFill><a:srgbClr val="{body_color}"/></a:solidFill></a:rPr>'
        f"<a:t>OmniShield  |  {number}</a:t></a:r></a:p></p:txBody></p:sp>"
        "</p:spTree></p:cSld></p:sld>"
    )


def pptx(slides: Sequence[Mapping[str, Any]], *, title: str, author: str = "OmniShield") -> bytes:
    if not slides:
        raise DocError("a deck needs at least one slide")
    parts: dict[str, bytes] = {}
    overrides = {
        "ppt/presentation.xml": "application/vnd.openxmlformats-officedocument.presentationml.presentation.main+xml",
        "ppt/slideMasters/slideMaster1.xml": "application/vnd.openxmlformats-officedocument.presentationml.slideMaster+xml",
        "ppt/slideLayouts/slideLayout1.xml": "application/vnd.openxmlformats-officedocument.presentationml.slideLayout+xml",
        "ppt/theme/theme1.xml": "application/vnd.openxmlformats-officedocument.theme+xml",
        "docProps/core.xml": "application/vnd.openxmlformats-package.core-properties+xml",
    }
    slide_ids = []
    presentation_rels = [
        '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/slideMaster" Target="slideMasters/slideMaster1.xml"/>',
        '<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/theme" Target="theme/theme1.xml"/>',
    ]
    for index, slide in enumerate(slides, start=1):
        parts[f"ppt/slides/slide{index}.xml"] = _slide(
            str(slide.get("title", "")),
            [str(line) for line in slide.get("lines", [])],
            number=index,
            dark=bool(slide.get("dark")),
        ).encode()
        parts[f"ppt/slides/_rels/slide{index}.xml.rels"] = (
            b'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            b'<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            b'<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/slideLayout" Target="../slideLayouts/slideLayout1.xml"/>'
            b"</Relationships>"
        )
        overrides[f"ppt/slides/slide{index}.xml"] = (
            "application/vnd.openxmlformats-officedocument.presentationml.slide+xml"
        )
        presentation_rels.append(
            f'<Relationship Id="rId{index + 2}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/slide" Target="slides/slide{index}.xml"/>'
        )
        slide_ids.append(f'<p:sldId id="{255 + index}" r:id="rId{index + 2}"/>')
    parts["ppt/presentation.xml"] = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<p:presentation xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" '
        'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" '
        'xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main">'
        '<p:sldMasterIdLst><p:sldMasterId id="2147483648" r:id="rId1"/></p:sldMasterIdLst>'
        f"<p:sldIdLst>{''.join(slide_ids)}</p:sldIdLst>"
        '<p:sldSz cx="12192000" cy="6858000"/><p:notesSz cx="6858000" cy="9144000"/>'
        "</p:presentation>"
    ).encode()
    parts["ppt/_rels/presentation.xml.rels"] = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        + "".join(presentation_rels)
        + "</Relationships>"
    ).encode()
    parts["ppt/slideMasters/slideMaster1.xml"] = SLIDE_MASTER.encode()
    parts["ppt/slideMasters/_rels/slideMaster1.xml.rels"] = (
        b'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        b'<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        b'<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/slideLayout" Target="../slideLayouts/slideLayout1.xml"/>'
        b'<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/theme" Target="../theme/theme1.xml"/>'
        b"</Relationships>"
    )
    parts["ppt/slideLayouts/slideLayout1.xml"] = SLIDE_LAYOUT.encode()
    parts["ppt/slideLayouts/_rels/slideLayout1.xml.rels"] = (
        b'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        b'<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        b'<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/slideMaster" Target="../slideMasters/slideMaster1.xml"/>'
        b"</Relationships>"
    )
    parts["ppt/theme/theme1.xml"] = THEME.encode()
    parts["docProps/core.xml"] = _core(title, author)
    parts["[Content_Types].xml"] = CONTENT_TYPES.format(overrides=_overrides(overrides)).encode()
    parts["_rels/.rels"] = ROOT_RELS.format(target="ppt/presentation.xml").encode()
    return _zip(parts)


def _pdf_text(text: str) -> str:
    return text.replace("\\", r"\\").replace("(", r"\(").replace(")", r"\)")


class _Pdf:
    def __init__(self, title: str, author: str) -> None:
        self.objects: list[bytes] = []
        self.pages: list[int] = []
        self.title = title
        self.author = author

    def add(self, payload: bytes) -> int:
        self.objects.append(payload)
        return len(self.objects)

    def reserve(self) -> int:
        self.objects.append(b"")
        return len(self.objects)

    def set(self, identifier: int, payload: bytes) -> None:
        self.objects[identifier - 1] = payload


def _wrap(text: str, width: int) -> list[str]:
    words = text.split()
    if not words:
        return [""]
    lines = []
    current = words[0]
    for word in words[1:]:
        candidate = f"{current} {word}"
        if len(candidate) <= width:
            current = candidate
        else:
            lines.append(current)
            current = word
    lines.append(current)
    return lines


def pdf(
    blocks: Sequence[Mapping[str, Any]],
    *,
    title: str,
    author: str = "OmniShield",
    page_width: int = 595,
    page_height: int = 842,
) -> bytes:
    if not blocks:
        raise DocError("a PDF needs at least one block")
    document = _Pdf(title, author)
    catalog = document.reserve()
    pages_object = document.reserve()
    font_regular = document.add(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>")
    font_bold = document.add(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>")
    font_mono = document.add(b"<< /Type /Font /Subtype /Type1 /BaseFont /Courier /Encoding /WinAnsiEncoding >>")
    font_italic = document.add(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Oblique /Encoding /WinAnsiEncoding >>")

    margin = 56
    usable = page_width - 2 * margin
    pages: list[list[str]] = []
    operations: list[str] = []
    y = page_height - margin
    images: list[int] = []

    def new_page() -> None:
        nonlocal operations, y
        if operations:
            pages.append(operations)
        operations = []
        y = page_height - margin

    def write(text: str, size: int, font: str, color: str = "0.1 0.1 0.15") -> None:
        nonlocal y
        if y < margin + 40:
            new_page()
        operations.append(
            f"BT /{font} {size} Tf {color} rg 1 0 0 1 {margin} {round(y, 2)} Tm ({_pdf_text(text)}) Tj ET"
        )
        y -= size * 1.45

    def paragraph(text: str, size: int = 11, font: str = "F1", width: int | None = None) -> None:
        for line in _wrap(text, width or int(usable / (size * 0.52))):
            write(line, size, font)

    for block in blocks:
        kind = block.get("type", "p")
        if kind == "pagebreak":
            new_page()
        elif kind == "h1":
            y -= 8
            paragraph(str(block["text"]), 22, "F2", int(usable / 11.4))
            operations.append(f"0.11 0.31 0.85 RG 2 w {margin} {round(y, 2)} m {margin + usable} {round(y, 2)} l S")
            y -= 10
        elif kind == "h2":
            y -= 6
            paragraph(str(block["text"]), 15, "F2", int(usable / 7.8))
            y -= 2
        elif kind == "h3":
            paragraph(str(block["text"]), 12, "F2", int(usable / 6.2))
        elif kind == "bullet":
            for index, line in enumerate(_wrap(f"- {block['text']}", int(usable / 5.7))):
                write(("  " if index else "") + line, 11, "F1")
        elif kind == "quote":
            for line in _wrap(str(block["text"]), int(usable / 5.7)):
                write(f"| {line}", 10, "F4", "0.35 0.38 0.45")
        elif kind == "code":
            for line in str(block["text"]).splitlines():
                write(line, 9, "F3", "0.15 0.2 0.3")
        elif kind == "table":
            rows = block["rows"]
            if not rows:
                continue
            columns = len(rows[0])
            column_width = usable / columns
            for row_index, row in enumerate(rows):
                if y < margin + 40:
                    new_page()
                if row_index == 0:
                    operations.append(
                        f"0.95 0.97 1 rg {margin} {round(y - 4, 2)} {round(usable, 2)} 16 re f"
                    )
                for column_index, cell in enumerate(row):
                    text = str(cell)
                    limit = max(4, int(column_width / 5.6))
                    if len(text) > limit:
                        text = text[: limit - 1] + "."
                    operations.append(
                        f"BT /{'F2' if row_index == 0 else 'F1'} 9 Tf 0.12 0.16 0.22 rg "
                        f"1 0 0 1 {round(margin + column_index * column_width + 4, 2)} "
                        f"{round(y, 2)} Tm ({_pdf_text(text)}) Tj ET"
                    )
                operations.append(
                    f"0.85 0.88 0.92 RG 0.5 w {margin} {round(y - 6, 2)} m "
                    f"{round(margin + usable, 2)} {round(y - 6, 2)} l S"
                )
                y -= 18
            y -= 6
        elif kind == "image":
            path = Path(block["path"])
            image = decode_png(path.read_bytes())
            width, height = image["width"], image["height"]
            pixels = bytearray()
            for row in image["rows"]:
                for pixel in row:
                    pixels.extend(pixel[:3] if isinstance(pixel, (list, tuple)) else (pixel, pixel, pixel))
            import zlib

            payload = zlib.compress(bytes(pixels), 6)
            identifier = document.add(
                f"<< /Type /XObject /Subtype /Image /Width {width} /Height {height} "
                f"/ColorSpace /DeviceRGB /BitsPerComponent 8 /Filter /FlateDecode "
                f"/Length {len(payload)} >>\nstream\n".encode()
                + payload
                + b"\nendstream"
            )
            images.append(identifier)
            scale = min(1.0, usable / width)
            draw_width, draw_height = width * scale, height * scale
            if y - draw_height < margin + 40:
                new_page()
            operations.append(
                f"q {round(draw_width, 2)} 0 0 {round(draw_height, 2)} {margin} "
                f"{round(y - draw_height, 2)} cm /Im{len(images)} Do Q"
            )
            y -= draw_height + 12
        else:
            paragraph(str(block.get("text", "")))

    if operations:
        pages.append(operations)
    if not pages:
        new_page()
        pages.append(operations)

    page_ids = []
    for index, page_operations in enumerate(pages, start=1):
        footer = (
            f"BT /F1 9 Tf 0.45 0.48 0.55 rg 1 0 0 1 {margin} 30 Tm "
            f"({_pdf_text(title)}  |  {index} / {len(pages)}) Tj ET"
        )
        content = "\n".join([*page_operations, footer]).encode("latin-1", "replace")
        content_id = document.add(
            f"<< /Length {len(content)} >>\nstream\n".encode() + content + b"\nendstream"
        )
        resources = (
            f"<< /Font << /F1 {font_regular} 0 R /F2 {font_bold} 0 R /F3 {font_mono} 0 R /F4 {font_italic} 0 R >>"
        )
        if images:
            resources += " /XObject << " + " ".join(
                f"/Im{position} {identifier} 0 R" for position, identifier in enumerate(images, start=1)
            ) + " >>"
        resources += " >>"
        page_ids.append(
            document.add(
                f"<< /Type /Page /Parent {pages_object} 0 R /MediaBox [0 0 {page_width} {page_height}] "
                f"/Resources {resources} /Contents {content_id} 0 R >>".encode()
            )
        )
    document.set(
        pages_object,
        f"<< /Type /Pages /Kids [{' '.join(f'{page} 0 R' for page in page_ids)}] /Count {len(page_ids)} >>".encode(),
    )
    document.set(catalog, f"<< /Type /Catalog /Pages {pages_object} 0 R >>".encode())
    info = document.add(
        (
            f"<< /Title ({_pdf_text(title)}) /Author ({_pdf_text(author)}) "
            "/Producer (OmniShield) /Creator (OmniShield) >>"
        ).encode("latin-1", "replace")
    )
    output = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = []
    for index, payload in enumerate(document.objects, start=1):
        offsets.append(len(output))
        output.extend(f"{index} 0 obj\n".encode())
        output.extend(payload)
        output.extend(b"\nendobj\n")
    start = len(output)
    output.extend(f"xref\n0 {len(document.objects) + 1}\n0000000000 65535 f \n".encode())
    for offset in offsets:
        output.extend(f"{offset:010d} 00000 n \n".encode())
    output.extend(
        f"trailer\n<< /Size {len(document.objects) + 1} /Root {catalog} 0 R /Info {info} 0 R >>\n"
        f"startxref\n{start}\n%%EOF\n".encode()
    )
    return bytes(output)


def markdown(blocks: Sequence[Mapping[str, Any]]) -> str:
    lines = []
    for block in blocks:
        kind = block.get("type", "p")
        if kind == "h1":
            lines += [f"# {block['text']}", ""]
        elif kind == "h2":
            lines += [f"## {block['text']}", ""]
        elif kind == "h3":
            lines += [f"### {block['text']}", ""]
        elif kind == "bullet":
            lines.append(f"- {block['text']}")
        elif kind == "quote":
            lines += [f"> {block['text']}", ""]
        elif kind == "code":
            lines += ["```", str(block["text"]), "```", ""]
        elif kind == "table":
            rows = block["rows"]
            if rows:
                lines.append("| " + " | ".join(str(cell) for cell in rows[0]) + " |")
                lines.append("|" + "|".join("---" for _ in rows[0]) + "|")
                for row in rows[1:]:
                    lines.append("| " + " | ".join(str(cell) for cell in row) + " |")
                lines.append("")
        elif kind == "image":
            lines += [f"![chart]({Path(block['path']).name})", ""]
        elif kind == "pagebreak":
            lines += ["---", ""]
        else:
            lines += [str(block.get("text", "")), ""]
    return "\n".join(lines).rstrip() + "\n"


def report(
    title: str,
    blocks: Sequence[Mapping[str, Any]],
    *,
    out_dir: str | Path,
    sheets: Mapping[str, Sequence[Sequence[Any]]] | None = None,
    slides: Sequence[Mapping[str, Any]] | None = None,
    author: str = "OmniShield",
) -> dict[str, Any]:
    target = Path(out_dir)
    target.mkdir(parents=True, exist_ok=True)
    slug = "".join(character if character.isalnum() else "-" for character in title.lower()).strip("-")
    written = {}
    markdown_path = target / f"{slug}.md"
    markdown_path.write_text(markdown(blocks), encoding="utf-8")
    written["markdown"] = markdown_path
    (target / f"{slug}.docx").write_bytes(docx(blocks, title=title, author=author))
    written["docx"] = target / f"{slug}.docx"
    (target / f"{slug}.pdf").write_bytes(pdf(blocks, title=title, author=author))
    written["pdf"] = target / f"{slug}.pdf"
    if sheets:
        (target / f"{slug}.xlsx").write_bytes(xlsx(sheets, title=title, author=author))
        written["xlsx"] = target / f"{slug}.xlsx"
    if slides:
        (target / f"{slug}.pptx").write_bytes(pptx(slides, title=title, author=author))
        written["pptx"] = target / f"{slug}.pptx"
    return {name: {"path": str(path), "bytes": path.stat().st_size} for name, path in written.items()}
