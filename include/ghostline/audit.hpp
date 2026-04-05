#pragma once

#include "ghostline/model.hpp"
#include <string>

class AuditTrail {
public:
    AuditTrail(const std::string& audit_log_path,
               const std::string& action_log_path,
               const std::string& audit_json_path,
               const std::string& action_json_path,
               const std::string& review_queue_dir);

    void record_event(const AuditEvent& event);
    void record_candidate(const FlowContext& flow, Direction direction, const Candidate& candidate, const CandidateDecision& decision);
    void record_observe_transition(const FlowContext& flow, Direction direction, const std::string& reason);
    void save_action_item(const ActionItem& item);

private:
    std::string audit_log_path_;
    std::string action_log_path_;
    std::string audit_json_path_;
    std::string action_json_path_;
    std::string review_queue_dir_;
};
