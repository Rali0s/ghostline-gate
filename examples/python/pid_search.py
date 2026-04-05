#!/usr/bin/env python3

import json
import subprocess
import sys


def main() -> int:
    args = sys.argv[1:]
    command = ["./build-local/ghostline_cli", "--search-json"] + args
    completed = subprocess.run(command, check=False, capture_output=True, text=True)
    if completed.returncode not in (0, 1):
        sys.stderr.write(completed.stderr)
        return completed.returncode

    payload = json.loads(completed.stdout or '{"processes":[]}')
    for process in payload.get("processes", []):
        print(f"PID {process['pid']} command={process['command']}")
        for socket in process.get("sockets", []):
            print(f"  {socket['state']} {socket['endpoint']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

