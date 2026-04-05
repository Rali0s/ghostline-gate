#!/usr/bin/env python3

import json
import pathlib
import re
import sys


def read_text(path: pathlib.Path) -> str:
    if not path.exists():
        return ""
    return path.read_text()


def assert_contains(label: str, text: str, needles: list[str]) -> None:
    for needle in needles:
        if needle not in text:
            raise AssertionError(f"{label} missing expected text: {needle!r}")


def assert_regex(label: str, text: str, patterns: list[str]) -> None:
    for pattern in patterns:
        if re.search(pattern, text, re.MULTILINE) is None:
            raise AssertionError(f"{label} missing expected pattern: {pattern!r}")


def assert_not_contains(label: str, text: str, needles: list[str]) -> None:
    for needle in needles:
        if needle in text:
            raise AssertionError(f"{label} contained unexpected text: {needle!r}")


def main() -> int:
    if len(sys.argv) != 3:
        raise SystemExit("usage: assert_simulation.py <fixture.json> <sim-output-dir>")

    fixture = json.loads(pathlib.Path(sys.argv[1]).read_text())
    out_dir = pathlib.Path(sys.argv[2])

    host_log = read_text(out_dir / "host.log")
    server_log = read_text(out_dir / "server.log")
    ghostline_log = read_text(out_dir / "ghostline.log")
    audit_log = read_text(out_dir / "ghostline_audit.log")
    actions_log = read_text(out_dir / "ghostline_actions.log")
    audit_json = read_text(out_dir / "ghostline_audit.jsonl")
    actions_json = read_text(out_dir / "ghostline_actions.jsonl")

    assert_contains("host.log", host_log, fixture.get("host_contains", []))
    assert_contains("server.log", server_log, fixture.get("server_contains", []))
    assert_contains("ghostline.log", ghostline_log, fixture.get("ghostline_contains", []))
    assert_not_contains("host.log", host_log, fixture.get("host_not_contains", []))
    assert_not_contains("server.log", server_log, fixture.get("server_not_contains", []))
    assert_not_contains("ghostline.log", ghostline_log, fixture.get("ghostline_not_contains", []))

    assert_regex("ghostline_audit.log", audit_log, fixture.get("audit_patterns", []))
    assert_not_contains("ghostline_audit.log", audit_log, fixture.get("audit_not_contains", []))
    assert_contains("ghostline_audit.jsonl", audit_json, fixture.get("audit_json_contains", []))
    assert_not_contains("ghostline_audit.jsonl", audit_json, fixture.get("audit_json_not_contains", []))

    expected_actions = fixture.get("actions_contains", [])
    if expected_actions:
        assert_contains("ghostline_actions.log", actions_log, expected_actions)
        expected_count = fixture.get("action_count")
        if expected_count is not None:
            actual_count = len([line for line in actions_log.splitlines() if line.strip()])
            if actual_count != expected_count:
                raise AssertionError(
                    f"ghostline_actions.log expected {expected_count} action items, found {actual_count}"
                )
    elif actions_log.strip():
        raise AssertionError("ghostline_actions.log contained unexpected action items")

    assert_not_contains("ghostline_actions.log", actions_log, fixture.get("actions_not_contains", []))
    assert_contains("ghostline_actions.jsonl", actions_json, fixture.get("actions_json_contains", []))
    assert_not_contains("ghostline_actions.jsonl", actions_json, fixture.get("actions_json_not_contains", []))

    print(f"assertions passed for {pathlib.Path(sys.argv[1]).name}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
