import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from omnishield.actions import (
    ActionError,
    DifferentialDrive,
    SafeFS,
    calculate,
    compose,
    describe,
    execute_python,
    http_get,
    pid_step,
    render_png,
    repair,
    run_command,
    sqlite_query,
    svg_chart,
    tone,
    write_wav,
)
from omnishield.vision import decode_png


def test_safe_fs_confines_every_path(tmp_path):
    sandbox = SafeFS(tmp_path)
    sandbox.write("notes/a.txt", "hello")
    assert sandbox.read("notes/a.txt") == "hello"
    assert sandbox.list("notes") == ["notes/a.txt"]
    assert sandbox.delete("notes/a.txt")["deleted"] == "notes/a.txt"
    with pytest.raises(ActionError, match="escapes"):
        sandbox.write("../outside.txt", "no")
    with pytest.raises(ActionError):
        sandbox.read("missing.txt")


def test_calculator_uses_an_ast_and_refuses_names():
    assert calculate("2 + 3 * 4")["value"] == 14
    assert calculate("sqrt(9) + abs(-2)")["value"] == 5
    assert calculate("2 ** 10")["value"] == 1024
    with pytest.raises(ActionError):
        calculate('__import__("os").system("id")')
    with pytest.raises(ActionError):
        calculate("secret + 1")
    with pytest.raises(ActionError):
        calculate("1 / 0")


def test_command_runner_needs_an_allow_list():
    result = run_command(["python3", "-c", "print('hi')"], allowed={"python3"})
    assert result["returncode"] == 0
    assert result["stdout"].strip() == "hi"
    with pytest.raises(ActionError, match="allow-list"):
        run_command(["rm", "-rf", "/"], allowed={"python3"})
    failing = run_command(["python3", "-c", "import sys; sys.exit(3)"], allowed={"python3"})
    assert failing["returncode"] == 3


def test_execute_python_runs_isolated():
    result = execute_python("print(6 * 7)")
    assert result["stdout"].strip() == "42"


def test_tool_composition_checks_types():
    tools = {
        "double": {"input": "int", "run": lambda value: value * 2},
        "label": {"input": "int", "run": lambda value: f"value={value}"},
    }
    result = compose(tools, ["double", "label"], initial=5)
    assert result["value"] == "value=10"
    assert [step["tool"] for step in result["steps"]] == ["double", "label"]
    with pytest.raises(ActionError, match="expects int"):
        compose({"label": tools["label"]}, ["label"], initial="text")


def test_tool_repair_coerces_then_drops_unknown_keys():
    def increment(count: int) -> int:
        return count + 1

    coerced = repair(increment, {"count": "5"}, schema={"count": int})
    assert coerced["ok"] is True
    assert coerced["repair"] == "coerced"
    assert coerced["result"] == 6

    dropped = repair(increment, {"count": 5, "extra": 1}, schema={"count": int})
    assert dropped["ok"] is True
    assert dropped["repair"] == "dropped_unknown"
    assert dropped["result"] == 6

    failed = repair(lambda required: required, {"other": 1})
    assert failed["ok"] is False


def test_http_get_is_pinned_to_allowed_hosts():
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            body = b"hello"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    port = server.server_address[1]
    try:
        url = f"http://127.0.0.1:{port}/page"
        assert http_get(url, allowed_hosts={"127.0.0.1"})["body"] == "hello"
        with pytest.raises(ActionError, match="allow-list"):
            http_get(url, allowed_hosts={"example.com"})
        with pytest.raises(ActionError, match="http"):
            http_get("file:///etc/passwd", allowed_hosts={"127.0.0.1"})
    finally:
        server.shutdown()
        server.server_close()


def test_sqlite_queries_and_summary_statistics():
    rows = [
        {"name": "amina", "team": "net"},
        {"name": "juma", "team": "net"},
        {"name": "neema", "team": "ai"},
    ]
    result = sqlite_query(rows, "SELECT team, COUNT(*) AS n FROM data GROUP BY team ORDER BY team")
    assert result["columns"] == ["team", "n"]
    assert result["rows"] == [{"team": "ai", "n": 1}, {"team": "net", "n": 2}]
    stats = describe([1, 2, 3, 4])
    assert stats["mean"] == 2.5
    assert stats["median"] == 2.5
    assert stats["stdev"] == pytest.approx(1.118, abs=0.01)
    with pytest.raises(ActionError):
        sqlite_query([], "SELECT 1")


def test_svg_chart_is_valid_text():
    chart = svg_chart({"a": [1, 3, 2], "b": [0, 2, 4]})
    assert chart.startswith("<svg")
    assert chart.count("<polyline") == 2
    assert chart.endswith("</svg>")
    assert 'fill="#1f77b4"' in chart


def test_png_and_wav_generation(tmp_path):
    png = render_png(4, 3, shade=lambda x, y: (x * 40, y * 60, 10))
    decoded = decode_png(png)
    assert (decoded["width"], decoded["height"]) == (4, 3)
    assert decoded["rows"][2][3] == (120, 120, 10)

    target = tmp_path / "tone.wav"
    write_wav(target, tone(440, rate=8000, seconds=0.25), rate=8000)
    with open(target, "rb") as handle:
        assert handle.read(4) == b"RIFF"


def test_differential_drive_and_pid():
    robot = DifferentialDrive(wheel_base=0.5)
    straight = robot.run([(1.0, 1.0)] * 10, dt=0.1)
    assert straight["pose"]["x"] == pytest.approx(1.0, abs=0.01)
    assert straight["pose"]["y"] == pytest.approx(0.0, abs=0.01)
    turning = DifferentialDrive().run([(-1.0, 1.0)] * 5, dt=0.1)
    assert turning["pose"]["theta"] > 0

    control = pid_step(10.0, kp=1.0, ki=0.1, kd=0.0, dt=1.0)
    assert control["output"] == pytest.approx(11.0)
    assert control["integral"] == pytest.approx(10.0)
