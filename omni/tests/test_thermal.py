import pytest

from omnishield.thermal import (
    Governor,
    ThermalError,
    cpu_usage,
    duty_cycle,
    temperature,
)


def test_duty_cycle_shrinks_under_load():
    assert duty_cycle(0.2) == 1.0
    assert duty_cycle(0.7) == 1.0
    assert duty_cycle(1.0) == pytest.approx(0.7)
    assert duty_cycle(0.9) == pytest.approx(0.778)
    with pytest.raises(ThermalError):
        duty_cycle(1.5)
    with pytest.raises(ThermalError):
        duty_cycle(0.5, target=0)


def test_governor_reads_the_host():
    state = Governor().state()
    assert 0 <= state["usage"] <= 1
    assert state["level"] in {"cool", "warm", "hot"}
    assert state["temperature_c"] is None or -20 < state["temperature_c"] < 150
    assert 0 < state["duty"] <= 1
    with pytest.raises(ThermalError):
        Governor(target=0)
    with pytest.raises(ThermalError):
        Governor(max_temp=-1)


def test_governor_runs_work_with_a_duty_cycle():
    governor = Governor(target=1.0, slice_s=0.001)
    result = governor.run(3, lambda index: index * 2)
    assert result["results"] == [0, 2, 4]
    assert result["steps"] == 3
    assert result["paused_s"] >= 0
    with pytest.raises(ThermalError):
        governor.run(0, lambda index: index)


def test_usage_is_a_fraction():
    usage = cpu_usage(0.02)
    assert 0 <= usage <= 1
    assert temperature() is None or -20 < temperature() < 150
