# Ghostline Phase 1 Runbook

## Product definition

Ghostline is a protocol-agnostic TCP relay platform with optional compiled-in plugins. It is not just a framed lab proxy. The product goal is to preserve original transport continuity first, then layer observation, framing, transformation, routing, reinjection, and audit on top without guessing when safety cannot be proven.

The design intent locked in from this thread is:

- Stage 1: observe and locate
- Stage 2: frame and transform
- Stage 2b: reframe
- Stage 3: route and end-transform
- Stage 4: audit and research

Phase 1 implements the CLI foundation for those stages on macOS first, while the architecture stays suitable for Linux, macOS, and Windows in the broader Phase 1 series.

## Non-negotiable rules

### Safe original priority

- Original delivery is mandatory.
- Mutation is optional.
- If Ghostline cannot prove the modified candidate is safe, it must send the original candidate.
- No partial modified candidate may leak onto the wire.
- If reinjection or replacement fails, the original must be sent.

### Exactness rules

- Preserve half-closes and direction independence.
- Preserve zero-length frames/messages when the active protocol permits them.
- Do not guess protocol ownership for unknown traffic.
- Byte-pattern triggers take priority over protocol-field triggers.
- Unknown traffic may use operator-defined framing/window rules, but Ghostline must not claim authoritative message boundaries unless a plugin or rule truly defines them.

### Failure rules

- Mutation failure means: keep the original path, drop the modified candidate, switch the affected flow to observe mode when risk is present, and create an operator action item.
- Observe downgrade is per-flow only, never global.
- PID/process identity is metadata and risk context, not the routing primitive.
- If PID drift or structural uncertainty is detected, mark the flow with `pid-drift-risk` and keep original delivery.

## Phase 1 operating stance

### Platform order

1. macOS CLI first
2. Qt embedded operator shell at the end of Phase 1
3. Linux and Windows support in the broader Phase 1 series

### Async-first stance

Ghostline should behave async-first, like a mailbox or MQ, even while the internal design keeps a path open for tighter inline timing later. Timing does not have to be the gating constraint in this first CLI implementation, but the architecture must not block a future timing-sensitive mode.

### GUI intent

The GUI is an embedded operator tool, not a remote daemon controller. It is intended for:

- live sessions
- operator visibility
- action items
- flow/plugin state

Workflow building is a bonus feature. The primary UI goal is to make the CLI easier to operate.

## Core architecture

### `TransportCore`

Responsibilities:

- accept inbound connections
- connect upstream
- preserve bidirectional passthrough
- preserve half-closes
- drain queued bytes before write shutdown
- hand pending byte windows to the plugin layer

Constraints:

- transport correctness wins over mutation
- no plugin may mutate the live outbound buffer directly
- all mutation must happen through staged candidates

### `PluginRegistry`

Responsibilities:

- own compiled-in plugin ordering
- prefer byte-window mutation rules when the operator configured them
- otherwise select protocol plugins for detection, framing, validation, and audit

Phase 1 plugin loading mode:

- compiled-in only
- no runtime dynamic loading yet

### `CandidateReplacePlugin`

This is the primary mutation model. It must:

- locate a replaceable window
- snapshot the `original candidate`
- build the `modified candidate`
- validate the modified candidate
- decide which candidate is released

It must never mutate the live outbound buffer directly.

### `AuditTrail`

Responsibilities:

- record protocol detection
- record candidate decisions
- record observe-mode transitions
- save operator action items for failed mutation workflows

## Candidate model

Every active mutation attempt must produce two candidates:

1. `original candidate`
2. `modified candidate`

The decision policy is:

- release modified only when validation passes and the timing/structure window is safe
- otherwise release original immediately

### Allowed size mutation

If a replacement changes size and the plugin can correctly rewrite dependent header bytes, Ghostline may allow it and mark `allow-size-mutated`.

### Blocked size mutation

If a replacement changes size and introduces downstream mutation risk, PID drift risk, or structural uncertainty:

- do not send the modified candidate
- mark `pid-drift-risk`
- keep or switch the flow to observe mode
- save an operator action item

### Live mutation workflow

When safe replacement cannot be released automatically, the follow-up workflow is:

1. locate header byte size
2. obtain delta difference size of the new message body
3. mutate dependent header/footer fields and the new message
4. review as a live mutation attempt in the next witness/iteration

## Flow and process policy

- Observation downgrade is per-flow only.
- Repeated failures do not automatically downgrade the whole engine.
- Process/PID drift is treated as a risk signal, not as an instruction to clone or replicate a process identity.
- The system must stay within the original flow context rather than behaving like a duplicated session.

## Trigger and framing policy

### Trigger priority

- Byte pattern matching is the highest-priority trigger class.
- Protocol-field triggers are secondary.

### Unknown traffic behavior

For traffic with no confirmed protocol plugin match:

- remain transport-correct
- support operator-defined framing/window rules
- support observation and candidate mutation through byte windows
- do not overclaim semantic understanding

### Replacement window model

The guiding pattern from the thread is:

`START > HEADER > MSG < FOOTER < END-BYTES`

Operationally, Ghostline should:

1. detect the start marker
2. buffer until the full replaceable window is present
3. build original and modified candidates
4. validate the modified form
5. release exactly one candidate path

The safest default is to replace only once the full window is buffered and validated.

## Routing and reinjection intent

The long-term routing model from the thread is:

- Source: divert
- Ghostline: replicate and deliver untouched
- Reinject: modified at a later time
- Conditional replacement: supported when safe

Phase 1 does not fully implement the routing matrix yet, but the runbook must preserve this target so future work does not collapse Ghostline back into a normal proxy.

## Protocol plugin expectations

Phase 1 includes compiled-in plugin targets for:

- MQTT
- RabbitMQ / RMQ
- ActiveMQ
- AMQP
- Azure Service Bus
- Kafka

### Phase 1 expectations by plugin

- All listed protocols exist as plugin targets in the binary.
- The active generic mutation path is byte-window based.
- The MQ-family plugins may begin as detection/audit and grow into protocol-owned framing and mutation over subsequent iterations.
- MQTT is the most natural early protocol to deepen first because message sensitivity and header-length behavior were repeatedly referenced in the thread.

### Encryption posture

Use open-source MQ headers and visible protocol structure where possible. If traffic is opaque or encrypted and Ghostline cannot safely work inside it yet, stay in observe mode and do not fabricate a mutation path.

## CLI and operator outputs

Phase 1 CLI must produce:

- audit events
- candidate decisions
- observe-mode flags
- action items for failed mutation workflows
- stable trigger, candidate, event, and action IDs for reviewable mutation sequences

When Ghostline flags a failed mutation, it should create a saved operator action item, not just a transient log line. The action item should point the operator toward the next framing/live-mutation iteration.

### Granular workflow identity

Each live mutation path, including raw mutation and MQTT mutation, should emit enough metadata to reconstruct the workflow:

- `trigger_id`
- `candidate_id`
- `event_id`
- `action_id`
- workflow stage
- per-flow event sequence

This is part of the review surface, not optional bookkeeping.

## Module responsibilities

### `TransportCore`

- preserve raw relay behavior
- buffer candidate windows safely
- maintain directional shutdown behavior

### `PluginRegistry`

- resolve plugin priority
- select byte-window or protocol-owned logic

### `CandidateReplacePlugin`

- build and validate staged candidates
- never mutate the live outbound buffer directly

### `ProtocolPlugin`

- detect protocol ownership
- define framing/window extraction
- define mutation rules when safe
- define validation rules
- define audit labels

### `RawLivePlugin`

- support protocol-agnostic live raw mutation
- frame raw traffic by fixed chunk or operator-defined end marker
- run through the same trigger/candidate/review pipeline as protocol-owned plugins
- preserve original delivery when size-changing raw mutation is unsafe

### `AuditTrail`

- persist protocol detections
- persist candidate releases/fallbacks
- persist action items

### `Qt Operator`

- embed the engine locally
- display target discovery and PID search results
- manage saved target profiles
- seed protocol target profiles for MQTT, RMQ, AMQP, ActiveMQ, Azure Service Bus, and Kafka
- display saved action items
- approve, reject, and replay review items

## Flow state machine

1. Accept connection
2. Connect upstream
3. Observe bytes
4. Match plugin or operator rule
5. If nothing matches, pass bytes through untouched
6. If plugin is observe-only, pass bytes through untouched and audit detection
7. If a replaceable window is defined:
   - hold bytes until the full window is present
   - build original and modified candidates
   - validate the modified candidate
   - release modified only when validation succeeds
   - otherwise release original, mark risk, and save an action item when needed
8. Drain queues
9. Preserve half-close
10. Finish the flow cleanly

## Candidate decision matrix

| Condition | Release | Flow flag | Action item |
| --- | --- | --- | --- |
| No plugin match | Original | None | No |
| Observe-only plugin | Original | None | No |
| Candidate valid, same size | Modified | None | No |
| Candidate valid, size changed, dependent fields rewritten | Modified | `allow-size-mutated` | No |
| Size changed, structure not provably safe | Original | `pid-drift-risk`, `observe-only` | Yes |
| Validation failed or mutation becomes unsafe/no-op | Original | `observe-only` when risk exists | Yes when risk exists |

## Implementation sequence

1. Stabilize the macOS CLI transport core
2. Keep original delivery exact and directional
3. Enable byte-window matching and candidate mutation
4. Persist audit and action items
5. Keep all six MQ-family plugins compiled in
6. Deepen protocol-owned framing and mutation per plugin
7. Ship the embedded Qt operator app for target discovery and review operations

## Acceptance criteria

- CLI builds on macOS without Linux-only APIs
- Raw passthrough works with no plugin match
- Byte-window mutation never leaks partial modified bytes
- Failed mutation falls back to original bytes
- Failed mutation creates an action item
- Per-flow observe-only downgrade does not affect unrelated flows
- Audit records candidate decisions, flags, and protocol detections
- The runbook remains aligned with the actual CLI behavior and the staged product target

## Operator workflow for failed mutation

1. Review the saved action item
2. Inspect the matched trigger and original candidate bytes
3. Locate the header size bytes
4. Compute the body delta
5. Rewrite dependent header/footer fields
6. Re-run the witness/live mutation attempt
7. If the rewrite is validated, promote it into plugin logic
8. If the rewrite is still unsafe, keep the flow in observe mode and preserve original delivery

## Explicit thread decisions captured here

This runbook intentionally captures the following decisions from the thread so future work does not regress them:

- protocol agnostic by default, plugin-aware when possible
- observe first, mutate later
- exact preservation over guessing
- byte pattern priority
- async-first behavior
- original wins on failure
- flow-only downgrade
- embedded Qt operator app for target discovery and review operations
- all six MQ-family plugins as Phase 1 targets
- action items for failed mutation, not just logs
