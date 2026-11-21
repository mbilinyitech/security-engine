import json
import os
from pathlib import Path

import pytest

from omnishield.render import RenderError
from omnishield.three_d import pathtrace

BINARY = Path(__file__).resolve().parent.parent / "organism" / "target" / "release" / "organism"
SCENE = {
    "width": 48,
    "height": 32,
    "samples": 1,
    "threads": 2,
    "bounces": 1,
    "camera": [0.0, 1.1, 3.8],
    "target": [0.0, 0.5, 0.0],
    "objects": [
        {"type": "plane", "y": 0.0, "colour": [0.7, 0.66, 0.6]},
        {"type": "sphere", "centre": [-0.5, 0.5, 0.0], "radius": 0.5, "colour": [0.2, 0.5, 0.9]},
        {"type": "box", "centre": [0.9, 0.4, -0.3], "half": 0.4, "colour": [0.6, 0.3, 0.25]},
    ],
}


@pytest.mark.skipif(not (BINARY.is_file() and os.access(BINARY, os.X_OK)), reason="Rust binary not built")
def test_pathtrace_renders_a_json_scene(tmp_path):
    scene = tmp_path / "scene.json"
    scene.write_text(json.dumps(SCENE), encoding="utf-8")
    result = pathtrace(scene, tmp_path / "scene.png")
    assert result["pixels"] == 48 * 32
    assert result["bounces"] == 1
    assert result["png_bytes"] > 500
    assert Path(result["png"]).read_bytes().startswith(b"\x89PNG")


def test_bad_scene_is_refused(tmp_path):
    scene = tmp_path / "bad.json"
    scene.write_text("{not json", encoding="utf-8")
    with pytest.raises(RenderError):
        pathtrace(scene, tmp_path / "x.png")
    missing = tmp_path / "missing.json"
    with pytest.raises(RenderError):
        pathtrace(missing, tmp_path / "x.png")
    empty = tmp_path / "empty.json"
    empty.write_text("{}", encoding="utf-8")
    with pytest.raises(RenderError):
        pathtrace(empty, tmp_path / "x.png", binary=tmp_path / "nope")
