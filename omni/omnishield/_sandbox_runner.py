"""Run one synthesized tool in an isolated child process.

Trusted code: this file is part of OmniShield, not of the tool. The tool source is
compiled and executed with a minimal namespace; the parent enforces CPU, memory,
file-size and descriptor limits, a wall-clock timeout, and a network namespace
when the platform allows it.
"""

import json
import sys


def main() -> int:
    if len(sys.argv) != 2:
        print(json.dumps({"error": "usage: runner TOOL_PATH"}))
        return 2
    path = sys.argv[1]
    try:
        payload = json.load(sys.stdin)
    except json.JSONDecodeError as exc:
        print(json.dumps({"error": f"payload is not JSON: {exc}"}))
        return 2
    namespace = {"__name__": "omnishield_tool", "__file__": path}
    try:
        with open(path, "rb") as handle:
            code = compile(handle.read(), path, "exec")
        exec(code, namespace)  # noqa: S102 - the source was checked before it was signed
        run = namespace.get("run")
        if not callable(run):
            print(json.dumps({"error": "tool does not define run(payload)"}))
            return 2
        result = run(payload)
        json.dump({"result": result}, sys.stdout)
        return 0
    except BaseException as exc:  # noqa: BLE001 - the parent reports it as a failed run
        print(json.dumps({"error": f"{type(exc).__name__}: {exc}"}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
