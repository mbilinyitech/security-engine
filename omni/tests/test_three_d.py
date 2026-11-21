import pytest

from omnishield.render import RenderError
from omnishield.three_d import (
    orbit,
    paint3d,
    plot3d,
    preset,
    scene3d,
    simulate_pendulum,
    simulate_projectile,
    video,
)


def test_scene_renders_with_python_or_rust():
    rendered = scene3d(96, 64, samples=1, engine="python")
    assert rendered["engine"] == "python"
    assert rendered["canvas"].width == 96
    assert rendered["canvas"].png().startswith(b"\x89PNG")
    with pytest.raises(RenderError):
        scene3d(4, 4)
    with pytest.raises(RenderError):
        scene3d(96, 64, engine="magic")


def test_camera_angle_changes_the_picture():
    front = paint3d(96, 64, angle=0.2)["canvas"].png()
    side = paint3d(96, 64, angle=1.2)["canvas"].png()
    assert front != side
    frames = orbit(6, 64, 40)
    assert len(frames) == 6
    assert frames[0].png() != frames[3].png()


def test_projectile_and_pendulum_are_physical():
    projectile = simulate_projectile(drag=0.0)
    assert projectile["range"] > 10
    assert projectile["apex"] > 1
    assert projectile["energy_change"] < 2.5
    assert projectile["rows"][0]["t"] == 0.0
    pendulum = simulate_pendulum()
    assert pendulum["period_s"] == pytest.approx(2.006, abs=0.25)
    assert pendulum["energy_drift"] < 0.1
    with pytest.raises(RenderError):
        simulate_projectile(speed=0)
    with pytest.raises(RenderError):
        simulate_pendulum(length=0)


def test_plot3d_draws_points(tmp_path):
    points = [(0.0, 0.0, 0.0), (1.0, 2.0, 0.5), (-1.0, 0.5, 2.0)]
    path = plot3d(points, width=200, height=140).save_png(tmp_path / "plot.png")
    assert path.stat().st_size > 800
    with pytest.raises(RenderError):
        plot3d([])


def test_presets_and_video(tmp_path, monkeypatch):
    assert preset("draft")["samples"] == 1
    assert preset("high")["threads"] == 8
    with pytest.raises(RenderError):
        preset("imax")
    monkeypatch.chdir(tmp_path)
    result = video(4, preset_name="draft")
    assert result["frames"] == 4
    assert result["gif"].is_file()
    assert result["gif"].read_bytes().startswith(b"GIF89a")
    assert len(result["frame_ms"]) == 4
    assert result["mean_frame_ms"] > 0
    assert result["total_ms"] >= result["mean_frame_ms"]
    with pytest.raises(RenderError):
        video(1, preset_name="draft")
