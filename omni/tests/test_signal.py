import pytest

from omnishield.signal import (
    SignalError,
    add_noise,
    clean,
    collect,
    detect_peaks,
    median_filter,
    moving_average,
    normalise,
    one_pole_highpass,
    one_pole_lowpass,
    remove_dc,
    resample,
    snr_db,
    spectrogram,
    synthesise,
    throughput,
    write_wav,
)
from omnishield.vision import dominant_frequency, read_wav


def test_synthesis_has_the_right_length_and_pitch():
    samples = synthesise([440], 0.25)
    assert len(samples) == 2000
    assert dominant_frequency(samples, 8000)["hz"] == pytest.approx(440, abs=10)
    assert len(synthesise([220, 440], 0.1)) == 800
    with pytest.raises(SignalError):
        synthesise([], 1)
    with pytest.raises(SignalError):
        synthesise([440], 0)


def test_noise_lowers_snr_and_cleaning_raises_it():
    reference = synthesise([440], 0.25)
    noisy = add_noise(reference, amplitude=0.3, seed=5)
    assert snr_db(reference, noisy) < 15
    cleaned = clean(noisy, reference=reference)
    assert cleaned["improvement_db"] > 0
    assert cleaned["snr_after_db"] > cleaned["snr_before_db"]
    assert [stage["stage"] for stage in cleaned["stages"]] == [
        "remove_dc",
        "despike",
        "smooth",
        "lowpass",
        "normalise",
    ]
    assert cleaned["samples_per_second"] > 100_000
    with pytest.raises(SignalError):
        clean([0.0, 1.0])
    with pytest.raises(SignalError):
        clean(noisy, reference=reference[:100])


def test_filters_do_what_their_names_say():
    dc = [0.5] * 100
    assert abs(sum(remove_dc(dc)) / 100) < 1e-9
    spike = [0.0] * 21
    spike[10] = 5.0
    assert median_filter(spike, 3)[10] < 1.0
    smoothed = moving_average([0, 0, 10, 0, 0], 3)
    assert smoothed[2] < 10
    assert one_pole_lowpass([1.0] * 10)[-1] == pytest.approx(1.0)
    assert abs(one_pole_highpass([1.0] * 10)[-1]) < 1e-6
    assert max(abs(value) for value in normalise([0.2, -0.4])) == pytest.approx(0.9)
    with pytest.raises(SignalError):
        median_filter([1, 2, 3], 4)
    with pytest.raises(SignalError):
        normalise([])


def test_peaks_resampling_and_spectrogram():
    peaks = detect_peaks(synthesise([100], 0.1), threshold=0.3, min_distance=5)
    assert len(peaks) >= 3
    assert all(peaks[index]["index"] < peaks[index + 1]["index"] for index in range(len(peaks) - 1))
    assert len(resample(synthesise([440], 0.1), 8000, 4000)) == 400
    assert len(resample(synthesise([440], 0.1), 8000, 8000)) == 800
    frame = spectrogram(synthesise([440], 0.1), window=128, hop=64)
    assert len(frame["frames"]) > 0
    assert len(frame["frames"][0]) == 64
    assert frame["frequencies"][1] > 0
    with pytest.raises(SignalError):
        spectrogram([0.1] * 10, window=128)


def test_wav_round_trip_and_collection(tmp_path):
    samples = synthesise([440], 0.05)
    path = write_wav(tmp_path / "tone.wav", samples)
    read = read_wav(str(path))
    assert read["rate"] == 8000
    assert len(read["samples"]) == len(samples)
    assert collect([[0.1, 0.2], [0.3]]) == [0.1, 0.2, 0.3]
    assert throughput([0.0] * 1000, 2.0) == 500000.0
    with pytest.raises(SignalError):
        collect([])
