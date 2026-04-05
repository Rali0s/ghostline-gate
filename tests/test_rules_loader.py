#!/usr/bin/env python3

import pathlib
import subprocess
import sys


ROOT = pathlib.Path(__file__).resolve().parents[1]


def run_rules(path: str, *vars: str) -> list[str]:
    command = ["python3", str(ROOT / "tools" / "resolve_rules.py"), "--rules", str(ROOT / path)]
    for item in vars:
        command.extend(["--var", item])
    completed = subprocess.run(command, check=True, capture_output=True, text=True)
    return [line for line in completed.stdout.splitlines() if line]


def expect_contains(args: list[str], expected: list[str], label: str) -> None:
    for item in expected:
        if item not in args:
            raise AssertionError(f"{label} missing expected arg {item!r}: {args!r}")


def main() -> int:
    json_args = run_rules("examples/rules/raw-live.json")
    expect_contains(
        json_args,
        ["--protocol-hint", "raw-live", "--raw-live", "--raw-find-text", "hello", "--actions-json", "ghostline_actions.jsonl"],
        "json rules",
    )

    jinja_args = run_rules(
        "examples/rules/mqtt_publish.jinja",
        "replacement_text=patched-payload",
        "mqtt_review_threshold=8",
        "audit_json_path=sim-output/mqtt/audit.jsonl",
        "action_json_path=sim-output/mqtt/actions.jsonl",
    )
    expect_contains(
        jinja_args,
        ["--protocol-hint", "mqtt", "--replace-text", "patched-payload", "--mqtt-review-threshold", "8"],
        "jinja rules",
    )

    hcl_args = run_rules("examples/rules/raw-live.tfvars")
    expect_contains(
        hcl_args,
        ["--protocol-hint", "raw-live", "--raw-live", "--raw-chunk-bytes", "1024", "--audit-json", "ghostline_audit.jsonl"],
        "hcl rules",
    )

    print("rules loader tests passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())

