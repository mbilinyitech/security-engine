import math
import struct
import wave

import pytest

from omnishield.vision import (
    VisionError,
    adapt,
    box_blur,
    connected_components,
    decode_png,
    dominant_frequency,
    encode_png,
    frame_difference,
    fuse_modalities,
    habituate,
    read_wav,
    saliency,
    sobel_edges,
    softmax_attention,
    template_match,
    threshold,
    to_gray,
)


def test_png_round_trip_preserves_pixels():
    image = [[(255, 0, 0), (0, 255, 0), (0, 0, 255)], [(1, 2, 3), (4, 5, 6), (7, 8, 9)]]
    decoded = decode_png(encode_png(image))
    assert (decoded["width"], decoded["height"]) == (3, 2)
    assert decoded["rows"] == image


def test_gray_png_round_trip():
    image = [[0, 64, 128], [192, 224, 255]]
    decoded = decode_png(encode_png(image, gray=True))
    assert decoded["rows"] == image
    with pytest.raises(VisionError):
        decode_png(b"not a png")


def test_grayscale_and_blur_keep_a_flat_field_flat():
    assert to_gray([[(255, 0, 0)]]) == [[76]]
    flat = [[100] * 6 for _ in range(6)]
    assert box_blur(flat, 2) == flat


def test_sobel_finds_the_border_of_a_square():
    image = [[0] * 9 for _ in range(9)]
    for y in range(3, 6):
        for x in range(3, 6):
            image[y][x] = 255
    edges = sobel_edges(image)
    assert edges[0][0] == 0
    assert edges[2][2] > 200
    assert max(max(row) for row in edges) == 255


def test_threshold_and_binding_count_objects():
    binary = [[0] * 10 for _ in range(5)]
    for x in range(3):
        binary[0][x] = 255
    for x in range(6, 9):
        binary[4][x] = 255
    components = connected_components(binary)
    assert len(components) == 2
    assert [item["area"] for item in components] == [3, 3]
    assert components[0]["box"] == (0, 0, 2, 0)
    assert threshold([[10, 200]], 100) == [[0, 255]]


def test_saliency_peaks_on_the_odd_pixel():
    image = [[50] * 9 for _ in range(9)]
    for y in range(3, 6):
        for x in range(3, 6):
            image[y][x] = 250
    heat = saliency(image)
    best = max((heat[y][x], x, y) for y in range(9) for x in range(9))
    assert best[1:] == (4, 4)
    assert best[0] == 1.0


def test_template_matching_finds_the_patch():
    image = [[0] * 12 for _ in range(12)]
    patch = [[10, 40], [80, 120]]
    for y in range(2):
        for x in range(2):
            image[5 + y][7 + x] = patch[y][x]
    result = template_match(image, patch)
    assert (result["x"], result["y"]) == (7, 5)
    assert result["score"] > 0.99


def test_frame_difference_marks_the_moving_pixel():
    first = [[0, 0], [0, 0]]
    second = [[0, 0], [0, 90]]
    motion = frame_difference([first, second])
    assert motion == [[0, 0], [0, 90]]
    with pytest.raises(VisionError):
        frame_difference([first])


def test_attention_weights_sum_to_one():
    result = softmax_attention([1.0, 2.0, 3.0])
    assert sum(result["weights"]) == pytest.approx(1.0, abs=0.01)
    assert result["weights"][2] > result["weights"][0]
    assert 0 < result["entropy"] <= 1


def test_modality_fusion_reports_agreement():
    agreed = fuse_modalities(
        [{"value": 0.8, "confidence": 0.9}, {"value": 0.82, "confidence": 0.7}]
    )
    assert agreed["disagree"] is False
    assert agreed["agreement"] > 0.9
    split = fuse_modalities([{"value": 0.0}, {"value": 1.0}])
    assert split["disagree"] is True


def test_habituation_and_adaptation():
    result = habituate(10.0, 3, rate=0.2)
    assert result["response"] == pytest.approx(5.12, abs=0.01)
    assert result["habituated"] is False
    assert habituate(10.0, 6, rate=0.2)["habituated"] is True
    adapted = adapt(0.0, 10.0, rate=0.3)
    assert adapted["level"] == pytest.approx(3.0)
    assert 0 < adapted["sensitivity"] <= 1


def test_wav_reading_and_dominant_frequency(tmp_path):
    rate = 8000
    samples = [
        int(20000 * math.sin(2 * math.pi * 440 * index / rate)) for index in range(rate // 2)
    ]
    target = tmp_path / "tone.wav"
    with wave.open(str(target), "wb") as handle:
        handle.setnchannels(1)
        handle.setsampwidth(2)
        handle.setframerate(rate)
        handle.writeframes(struct.pack("<" + "h" * len(samples), *samples))
    read = read_wav(str(target))
    assert read["rate"] == rate
    assert read["duration_s"] == pytest.approx(0.5, abs=0.01)
    assert read["peak"] > 19000
    frequency = dominant_frequency(read["samples"], rate)
    assert frequency["hz"] == pytest.approx(440, abs=10)
