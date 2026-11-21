import pytest

from omnishield.speech import (
    KeywordSpotter,
    SpeechError,
    dtw_distance,
    formant_speak,
    listen,
    mfcc,
    speak,
)
from omnishield.vision import read_wav


def test_mfcc_shape_and_dtw_identity():
    frames = mfcc(formant_speak("habari"))
    assert len(frames) > 10
    assert len(frames[0]) == 13
    assert dtw_distance(frames, frames) == 0.0
    other = mfcc(formant_speak("asante"))
    assert dtw_distance(frames, other) > 0
    with pytest.raises(SpeechError):
        mfcc([])
    with pytest.raises(SpeechError):
        mfcc([0.1] * 100, rate=2000)


def test_spotter_knows_only_its_words():
    spotter = KeywordSpotter(threshold=60.0)
    assert spotter.train("habari", formant_speak("habari"))["frames"] > 10
    spotter.train("asante", formant_speak("asante"))
    assert spotter.recognise(formant_speak("habari", speed=1.05))["word"] == "habari"
    assert spotter.recognise(formant_speak("asante"))["word"] == "asante"
    unknown = spotter.recognise(formant_speak("zzz"))
    assert unknown["word"] is None or unknown["distance"] > 0
    with pytest.raises(SpeechError):
        KeywordSpotter().recognise(formant_speak("habari"))
    with pytest.raises(SpeechError):
        spotter.train("  ", formant_speak("habari"))


def test_speak_writes_audio_and_listen_reads_it(tmp_path):
    spoken = speak("habari", tmp_path / "habari.wav")
    assert spoken["seconds"] > 0.2
    assert spoken["synthesised_ms"] > 0
    wav = read_wav(spoken["path"])
    assert wav["rate"] == 8000
    spotter = KeywordSpotter(threshold=60.0)
    spotter.train("habari", formant_speak("habari"))
    result = listen(spoken["path"], spotter)
    assert result["word"] == "habari"
    with pytest.raises(SpeechError):
        speak("   ", tmp_path / "x.wav")
    with pytest.raises(SpeechError):
        formant_speak("habari", speed=0)
