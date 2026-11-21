import random

import pytest

from omnishield.render import Canvas, RenderError, denoise, noise_level


def test_denoise_reduces_grain_and_keeps_edges():
    canvas = Canvas(40, 24)
    random.seed(11)
    for y in range(24):
        for x in range(40):
            base = 130 if x < 20 else 35
            value = max(0, min(255, base + random.randint(-22, 22)))
            canvas.set(x, y, (value, value, value))
    before = noise_level(canvas)
    cleaned = denoise(canvas)
    after = noise_level(cleaned)
    assert after < before * 0.75
    assert cleaned.get(19, 12)[0] > cleaned.get(20, 12)[0]
    with pytest.raises(RenderError):
        denoise(canvas, radius=0)


def test_flat_image_stays_flat():
    canvas = Canvas(16, 16, (90, 120, 150))
    cleaned = denoise(canvas)
    assert cleaned.get(8, 8) == (90, 120, 150)
    assert noise_level(cleaned) == 0.0
