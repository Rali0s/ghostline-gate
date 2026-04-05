#include "ghostline/audit.hpp"
#include "ghostline/operator_state.hpp"

#include <chrono>
#include <fstream>
#include <iomanip>
#include <sstream>

namespace {

std::string direction_name(Direction direction) {
    return direction == Direction::ClientToServer ? "client_to_server" : "server_to_client";
}

std::string flag_name(FlowFlag flag) {
    switch (flag) {
        case FlowFlag::ObserveOnly: return "observe-only";
        case FlowFlag::AllowSizeMutated: return "allow-size-mutated";
        case FlowFlag::PidDriftRisk: return "pid-drift-risk";
    }
    return "unknown";
}

std::string stage_name(WorkflowStage stage) {
    switch (stage) {
        case WorkflowStage::Observe: return "observe";
        case WorkflowStage::Triggered: return "triggered";
        case WorkflowStage::Framed: return "framed";
        case WorkflowStage::CandidateBuilt: return "candidate-built";
        case WorkflowStage::CandidateReviewed: return "candidate-reviewed";
        case WorkflowStage::ReleasedOriginal: return "released-original";
        case WorkflowStage::ReleasedModified: return "released-modified";
        case WorkflowStage::ObserveTransition: return "observe-transition";
        case WorkflowStage::ActionCreated: return "action-created";
    }
    return "unknown";
}

std::string bytes_to_hex(const ByteVec& bytes) {
    std::ostringstream out;
    out << std::hex << std::setfill('0');
    for (ByteVec::size_type i = 0; i < bytes.size(); ++i) {
        out << std::setw(2) << static_cast<unsigned>(bytes[i]);
    }
    return out.str();
}

std::string format_flags(const std::vector<FlowFlag>& flags) {
    std::ostringstream out;
    for (std::size_t i = 0; i < flags.size(); ++i) {
        if (i != 0) out << ",";
        out << flag_name(flags[i]);
    }
    return out.str();
}

std::string json_escape(const std::string& value) {
    std::ostringstream out;
    for (char ch : value) {
        switch (ch) {
            case '\\': out << "\\\\"; break;
            case '"': out << "\\\""; break;
            case '\n': out << "\\n"; break;
            case '\r': out << "\\r"; break;
            case '\t': out << "\\t"; break;
            default: out << ch; break;
        }
    }
    return out.str();
}

std::string direction_json(Direction direction) {
    return direction == Direction::ClientToServer ? "client_to_server" : "server_to_client";
}

std::string flags_to_json(const std::vector<FlowFlag>& flags) {
    std::ostringstream out;
    out << "[";
    for (std::size_t i = 0; i < flags.size(); ++i) {
        if (i != 0) out << ",";
        out << "\"" << flag_name(flags[i]) << "\"";
    }
    out << "]";
    return out.str();
}

std::uint64_t now_ns() {
    using namespace std::chrono;
    return duration_cast<nanoseconds>(steady_clock::now().time_since_epoch()).count();
}

void append_line(const std::string& path, const std::string& line) {
    std::ofstream out(path.c_str(), std::ios::app);
    out << line << "\n";
}

} // namespace

AuditTrail::AuditTrail(const std::string& audit_log_path,
                       const std::string& action_log_path,
                       const std::string& audit_json_path,
                       const std::string& action_json_path,
                       const std::string& review_queue_dir)
    : audit_log_path_(audit_log_path),
      action_log_path_(action_log_path),
      audit_json_path_(audit_json_path),
      action_json_path_(action_json_path),
      review_queue_dir_(review_queue_dir) {}

void AuditTrail::record_event(const AuditEvent& event) {
    std::ostringstream line;
    line << "ts=" << event.timestamp_ns
         << " event_id=" << event.event_id
         << " trigger_id=" << event.trigger_id
         << " candidate_id=" << event.candidate_id
         << " flow=" << event.flow_id
         << " seq=" << event.sequence
         << " dir=" << direction_name(event.direction)
         << " plugin=" << event.plugin_name
         << " type=" << event.event_type
         << " stage=" << stage_name(event.workflow_stage)
         << " flags=" << format_flags(event.flags)
         << " message=\"" << event.message << "\""
         << " original=" << bytes_to_hex(event.original_bytes)
         << " modified=" << bytes_to_hex(event.modified_bytes);
    append_line(audit_log_path_, line.str());

    if (!audit_json_path_.empty()) {
        std::ostringstream json;
        json << "{"
             << "\"ts\":" << event.timestamp_ns
             << ",\"event_id\":\"" << json_escape(event.event_id) << "\""
             << ",\"trigger_id\":\"" << json_escape(event.trigger_id) << "\""
             << ",\"candidate_id\":\"" << json_escape(event.candidate_id) << "\""
             << ",\"flow\":" << event.flow_id
             << ",\"seq\":" << event.sequence
             << ",\"dir\":\"" << direction_json(event.direction) << "\""
             << ",\"plugin\":\"" << json_escape(event.plugin_name) << "\""
             << ",\"type\":\"" << json_escape(event.event_type) << "\""
             << ",\"stage\":\"" << stage_name(event.workflow_stage) << "\""
             << ",\"flags\":" << flags_to_json(event.flags)
             << ",\"message\":\"" << json_escape(event.message) << "\""
             << ",\"original\":\"" << bytes_to_hex(event.original_bytes) << "\""
             << ",\"modified\":\"" << bytes_to_hex(event.modified_bytes) << "\""
             << "}";
        append_line(audit_json_path_, json.str());
    }
}

void AuditTrail::record_candidate(const FlowContext& flow, Direction direction, const Candidate& candidate, const CandidateDecision& decision) {
    AuditEvent event;
    event.event_id = candidate.candidate_id.empty() ? "" : candidate.candidate_id + "-result";
    event.flow_id = flow.flow_id;
    event.direction = direction;
    event.plugin_name = candidate.plugin_name;
    event.event_type = "candidate";
    event.message = candidate.note
        + " validation=" + decision.validation_label
        + " detail=" + decision.validation_detail
        + " fallback=" + decision.fallback_reason;
    event.trigger_id = candidate.trigger_id;
    event.candidate_id = candidate.candidate_id;
    event.original_bytes = candidate.original_bytes;
    event.modified_bytes = candidate.modified_bytes;
    event.flags = flow.flags;
    event.workflow_stage = decision.release == CandidateRelease::ReleaseModified
        ? WorkflowStage::ReleasedModified
        : WorkflowStage::ReleasedOriginal;
    event.sequence = flow.event_sequence;
    event.timestamp_ns = now_ns();
    record_event(event);
}

void AuditTrail::record_observe_transition(const FlowContext& flow, Direction direction, const std::string& reason) {
    AuditEvent event;
    event.event_id = "event-" + std::to_string(flow.flow_id) + "-observe-transition";
    event.flow_id = flow.flow_id;
    event.direction = direction;
    event.plugin_name = flow.active_plugin;
    event.event_type = "observe-transition";
    event.message = reason;
    event.flags = flow.flags;
    event.workflow_stage = WorkflowStage::ObserveTransition;
    event.sequence = flow.event_sequence;
    event.timestamp_ns = now_ns();
    record_event(event);
}

void AuditTrail::save_action_item(const ActionItem& item) {
    std::ostringstream line;
    line << "ts=" << item.created_at_ns
         << " action_id=" << item.action_id
         << " trigger_id=" << item.trigger_id
         << " candidate_id=" << item.candidate_id
         << " flow=" << item.flow_id
         << " plugin=" << item.plugin_name
         << " stage=" << stage_name(item.workflow_stage)
         << " title=\"" << item.title << "\""
         << " detail=\"" << item.detail << "\"";
    append_line(action_log_path_, line.str());

    if (!action_json_path_.empty()) {
        std::ostringstream json;
        json << "{"
             << "\"ts\":" << item.created_at_ns
             << ",\"action_id\":\"" << json_escape(item.action_id) << "\""
             << ",\"trigger_id\":\"" << json_escape(item.trigger_id) << "\""
             << ",\"candidate_id\":\"" << json_escape(item.candidate_id) << "\""
             << ",\"flow\":" << item.flow_id
             << ",\"plugin\":\"" << json_escape(item.plugin_name) << "\""
             << ",\"stage\":\"" << stage_name(item.workflow_stage) << "\""
             << ",\"title\":\"" << json_escape(item.title) << "\""
             << ",\"detail\":\"" << json_escape(item.detail) << "\""
             << "}";
        append_line(action_json_path_, json.str());
    }

    if (!review_queue_dir_.empty()) {
        save_review_item(review_queue_dir_, item);
    }
}
