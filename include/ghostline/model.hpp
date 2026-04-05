#pragma once

#include "core/types.hpp"
#include <cstdint>
#include <string>
#include <vector>

enum class Direction {
    ClientToServer = 0,
    ServerToClient = 1,
};

enum class FlowFlag {
    ObserveOnly,
    AllowSizeMutated,
    PidDriftRisk,
};

enum class CandidateRelease {
    ReleaseOriginal,
    ReleaseModified,
};

enum class ValidationOutcome {
    ValidationPassed,
    ValidationFallbackOriginal,
    ValidationObserveOnly,
};

enum class WorkflowStage {
    Observe,
    Triggered,
    Framed,
    CandidateBuilt,
    CandidateReviewed,
    ReleasedOriginal,
    ReleasedModified,
    ObserveTransition,
    ActionCreated,
};

struct FlowContext {
    std::uint32_t flow_id = 0;
    std::int64_t pid_hint = -1;
    std::string preferred_plugin;
    std::string active_plugin;
    std::string observe_reason;
    std::string last_packet_type;
    std::uint64_t event_sequence = 0;
    std::uint64_t trigger_sequence = 0;
    std::uint64_t candidate_sequence = 0;
    bool observe_only = false;
    std::vector<FlowFlag> flags;
};

struct Candidate {
    std::string trigger_id;
    std::string candidate_id;
    std::string plugin_name;
    std::string trigger_label;
    ByteVec original_bytes;
    ByteVec modified_bytes;
    std::size_t header_size = 0;
    std::size_t footer_size = 0;
    std::size_t payload_offset = 0;
    std::size_t payload_size = 0;
    long long size_delta = 0;
    bool allow_size_mutated = false;
    bool pid_drift_risk = false;
    bool valid = false;
    std::string packet_type;
    std::string protocol_note;
    std::string review_label;
    WorkflowStage workflow_stage = WorkflowStage::CandidateBuilt;
    std::string note;
};

struct CandidateDecision {
    CandidateRelease release = CandidateRelease::ReleaseOriginal;
    ValidationOutcome outcome = ValidationOutcome::ValidationFallbackOriginal;
    bool observe_only = false;
    bool create_action_item = false;
    bool review_required = false;
    std::string validation_label;
    std::string validation_detail;
    std::string fallback_reason;
    std::string trigger_id;
    std::string candidate_id;
    std::string review_reason;
    std::string action_title;
    std::string action_detail;
    WorkflowStage workflow_stage = WorkflowStage::CandidateReviewed;
};

struct ActionItem {
    std::string action_id;
    std::string trigger_id;
    std::string candidate_id;
    std::uint32_t flow_id = 0;
    std::string plugin_name;
    Direction direction = Direction::ClientToServer;
    std::string title;
    std::string detail;
    std::string validation_label;
    std::string fallback_reason;
    std::string original_hex;
    std::string modified_hex;
    std::string review_status = "pending";
    std::string decision_note;
    std::uint32_t replay_count = 0;
    WorkflowStage workflow_stage = WorkflowStage::ActionCreated;
    std::uint64_t created_at_ns = 0;
};

struct AuditEvent {
    std::string event_id;
    std::string trigger_id;
    std::string candidate_id;
    std::uint32_t flow_id = 0;
    Direction direction = Direction::ClientToServer;
    std::string plugin_name;
    std::string event_type;
    std::string message;
    ByteVec original_bytes;
    ByteVec modified_bytes;
    std::vector<FlowFlag> flags;
    WorkflowStage workflow_stage = WorkflowStage::Observe;
    std::uint64_t sequence = 0;
    std::uint64_t timestamp_ns = 0;
};
