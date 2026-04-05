#!/usr/bin/env python3

import argparse
import json
import pathlib
import re
import sys


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--rules", required=True)
    parser.add_argument("--var", action="append", default=[])
    return parser.parse_args()


def parse_vars(pairs: list[str]) -> dict[str, str]:
    values: dict[str, str] = {}
    for pair in pairs:
        if "=" not in pair:
            raise SystemExit(f"invalid --var entry: {pair!r}")
        key, value = pair.split("=", 1)
        values[key] = value
    return values


def render_jinja_lite(text: str, variables: dict[str, str]) -> str:
    pattern = re.compile(r"{{\s*([a-zA-Z0-9_.-]+)\s*}}")

    def repl(match: re.Match[str]) -> str:
        key = match.group(1)
        if key not in variables:
            raise SystemExit(f"missing template variable: {key}")
        return variables[key]

    return pattern.sub(repl, text)


def parse_scalar(value: str):
    value = value.strip().rstrip(",")
    if value.startswith('"') and value.endswith('"'):
        return json.loads(value)
    if value in ("true", "false"):
        return value == "true"
    if re.fullmatch(r"-?\d+", value):
        return int(value)
    raise SystemExit(f"unsupported HCL/Terraform value: {value!r}")


def parse_hcl_lite(text: str) -> dict:
    data: dict[str, object] = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or line.startswith("//"):
            continue
        if "#" in line:
            line = line.split("#", 1)[0].strip()
        if "//" in line:
            line = line.split("//", 1)[0].strip()
        if not line:
            continue
        match = re.match(r"([A-Za-z0-9_.-]+)\s*=\s*(.+)$", line)
        if not match:
            raise SystemExit(f"unsupported HCL/Terraform rule line: {raw_line!r}")
        key, value = match.groups()
        data[key] = parse_scalar(value)
    return data


def load_rule_data(path: pathlib.Path, variables: dict[str, str]) -> dict:
    text = path.read_text()
    suffixes = "".join(path.suffixes).lower()

    if path.suffix.lower() in (".j2", ".jinja", ".jinja2"):
        rendered = render_jinja_lite(text, variables)
        return json.loads(rendered)

    if suffixes.endswith(".tf.json") or suffixes.endswith(".hcl.json") or path.suffix.lower() == ".json":
        return json.loads(text)

    if path.suffix.lower() in (".tf", ".tfvars", ".hcl"):
        return parse_hcl_lite(text)

    raise SystemExit(f"unsupported rules format: {path.name}")


def bool_arg(name: str, value: object) -> list[str]:
    return [name] if bool(value) else []


def normalize_to_args(data: dict) -> list[str]:
    args: list[str] = []

    positional = []
    for key in ("listen_port", "upstream_host", "upstream_port"):
        if key in data:
            positional.append(str(data[key]))
    if positional:
        if len(positional) != 3:
            raise SystemExit("rules must define listen_port, upstream_host, and upstream_port together")
        args.extend(positional)

    mapping = [
        ("start_marker_hex", "--start-hex"),
        ("end_marker_hex", "--end-hex"),
        ("replace_text", "--replace-text"),
        ("raw_find_text", "--raw-find-text"),
        ("raw_chunk_bytes", "--raw-chunk-bytes"),
        ("mutate_direction", "--mutate-direction"),
        ("raw_review_threshold", "--raw-review-threshold"),
        ("raw_review_threshold_bytes", "--raw-review-threshold"),
        ("mqtt_review_threshold", "--mqtt-review-threshold"),
        ("mqtt_review_threshold_bytes", "--mqtt-review-threshold"),
        ("byte_review_threshold", "--byte-review-threshold"),
        ("byte_window_review_threshold_bytes", "--byte-review-threshold"),
        ("max_plugin_buffer", "--max-plugin-buffer"),
        ("max_plugin_buffer_bytes", "--max-plugin-buffer"),
        ("protocol_hint", "--protocol-hint"),
        ("audit_log_path", "--audit-log"),
        ("action_log_path", "--action-log"),
        ("audit_json_path", "--audit-json"),
        ("action_json_path", "--actions-json"),
    ]

    args.extend(bool_arg("--raw-live", data.get("raw_live", False) or data.get("raw_live_mode", False)))
    args.extend(bool_arg("--rewrite-u32-prefix", data.get("rewrite_u32_prefix", False)))

    for key, flag in mapping:
        if key in data:
            args.extend([flag, str(data[key])])

    return args


def main() -> int:
    ns = parse_args()
    rules_path = pathlib.Path(ns.rules)
    variables = parse_vars(ns.var)
    data = load_rule_data(rules_path, variables)
    for arg in normalize_to_args(data):
        print(arg)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

