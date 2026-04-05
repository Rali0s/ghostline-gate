# Ghostline CLI Cheatsheet

## Man Page

```bash
MANPATH="$PWD/man:${MANPATH}" man ghostline_cli
```

## Fast Help

```bash
./build-local/ghostline_cli -h
./build-local/ghostline_cli --help-rules
./build-local/ghostline_cli --help-search
./build-local/ghostline_cli --help-examples
./build-local/ghostline_cli --help-cheatsheet
```

## Find a Target Process

```bash
./build-local/ghostline_cli --search-pid ollama
./build-local/ghostline_cli --search-port 1883 --listen-only
./build-local/ghostline_cli --search-pid python --search-port 443 --established-only
./build-local/ghostline_cli --search-json --search-pid ollama
```

## Raw Live Mutation

```bash
./build-local/ghostline_cli 7777 127.0.0.1 8888 \
  --protocol-hint raw-live \
  --raw-live \
  --raw-find-text hello \
  --replace-text patch \
  --mutate-direction c2s \
  --raw-review-threshold 8
```

## MQTT Mutation

```bash
./build-local/ghostline_cli 7777 127.0.0.1 1883 \
  --protocol-hint mqtt \
  --replace-text patched-payload \
  --mutate-direction c2s \
  --mqtt-review-threshold 8
```

## Rules-Driven Control

JSON:
```bash
./build-local/ghostline_cli 7777 127.0.0.1 8888 \
  --rules examples/rules/raw-live.json
```

Jinja-style JSON:
```bash
./build-local/ghostline_cli 7777 127.0.0.1 1883 \
  --rules examples/rules/mqtt_publish.jinja \
  --rules-var replacement_text=patched-payload \
  --rules-var mqtt_review_threshold=8 \
  --rules-var audit_json_path=sim-output/mqtt/audit.jsonl \
  --rules-var action_json_path=sim-output/mqtt/actions.jsonl
```

HCL/Terraform-style:
```bash
./build-local/ghostline_cli 7777 127.0.0.1 8888 \
  --rules examples/rules/raw-live.tfvars
```

## JSONL Streams

```bash
./build-local/ghostline_cli 7777 127.0.0.1 8888 \
  --rules examples/rules/raw-live.json \
  --audit-json ghostline_audit.jsonl \
  --actions-json ghostline_actions.jsonl
```

## Sim Harness

```bash
MODE=raw ./sim.bash
MODE=mqtt ./sim.bash
```

## Useful Answers

- Find a process: `ghostline_cli --search-pid <name>`
- Find listeners: `ghostline_cli --search-port <port> --listen-only`
- Emit machine-readable discovery: `ghostline_cli --search-json ...`
- Emit machine-readable audit/action streams: `--audit-json` and `--actions-json`
- Load reproducible controls from files: `--rules`
