import pytest

from omnishield.render import (
    Canvas,
    RenderError,
    animate,
    art,
    chart,
    downsample,
    save_gif,
)
from omnishield.vision import decode_png


def test_canvas_draws_and_encodes_a_real_png():
    canvas = Canvas(40, 30, (10, 20, 30))
    assert canvas.get(0, 0) == (10, 20, 30)
    canvas.fill_rect(5, 5, 10, 4, (255, 0, 0))
    assert canvas.get(6, 6) == (255, 0, 0)
    canvas.set(-1, -1, (1, 2, 3))
    canvas.set(1000, 1000, (1, 2, 3))
    canvas.circle(20, 15, 5, (0, 255, 0))
    canvas.line(0, 0, 39, 29, (0, 0, 255))
    decoded = decode_png(canvas.png())
    assert decoded["width"] == 40
    assert decoded["height"] == 30
    assert len(decoded["rows"]) == 30
    with pytest.raises(RenderError):
        Canvas(0, 10)


def test_text_gradient_and_polygon_change_pixels():
    plain = Canvas(80, 20)
    written = Canvas(80, 20)
    written.text(2, 2, "AB1", (0, 0, 0))
    assert plain.png() != written.png()
    gradient = Canvas(4, 4)
    gradient.gradient((0, 0, 0), (255, 255, 255))
    assert gradient.get(0, 0) == (0, 0, 0)
    assert gradient.get(0, 3) == (255, 255, 255)
    triangle = Canvas(20, 20)
    triangle.polygon([(2, 2), (18, 2), (10, 18)], (200, 10, 10))
    assert triangle.get(10, 8) == (200, 10, 10)
    with pytest.raises(RenderError):
        triangle.polygon([(1, 1), (2, 2)], (0, 0, 0))


def test_chart_art_and_downsample_are_deterministic():
    first = chart([1, 4, 2, 8], title="T")
    second = chart([1, 4, 2, 8], title="T")
    assert first.png() == second.png()
    assert art(7, width=60, height=40).png() == art(7, width=60, height=40).png()
    assert art(7, width=60, height=40).png() != art(8, width=60, height=40).png()
    smooth = downsample(Canvas(20, 20, (0, 0, 0)), 2)
    assert (smooth.width, smooth.height) == (10, 10)
    assert smooth.get(0, 0) == (0, 0, 0)
    with pytest.raises(RenderError):
        chart([])


def test_gif_animation_is_a_real_gif(tmp_path):
    frames = animate(frames=4, width=48, height=32)
    path = save_gif(frames, tmp_path / "anim.gif", delay_cs=5)
    data = path.read_bytes()
    assert data.startswith(b"GIF89a")
    assert data.endswith(b";")
    assert data.count(b"\x21\xf9\x04") == 4
    assert b"NETSCAPE2.0" in data
    with pytest.raises(RenderError):
        save_gif([], tmp_path / "empty.gif")
    with pytest.raises(RenderError):
        save_gif([Canvas(10, 10), Canvas(20, 20)], tmp_path / "bad.gif")
