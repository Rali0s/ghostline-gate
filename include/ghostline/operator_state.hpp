#pragma once

#include "ghostline/model.hpp"
#include "ghostline/pid_search.hpp"

#include <string>
#include <vector>

struct TargetProfile {
    std::string label;
    PidSearchQuery query;
    std::vector<ProcessSocketEntry> matches;
};

std::string bytes_to_hex_string(const ByteVec& bytes);

void save_target_profile(const std::string& path, const TargetProfile& profile);
TargetProfile load_target_profile(const std::string& path);
std::vector<std::string> list_target_profiles(const std::string& directory);
std::string target_profile_to_json(const TargetProfile& profile);
std::vector<TargetProfile> default_protocol_target_profiles();
std::vector<std::string> seed_protocol_target_profiles(const std::string& directory);

void save_review_item(const std::string& queue_dir, const ActionItem& item);
ActionItem load_review_item(const std::string& path);
std::vector<ActionItem> list_review_items(const std::string& queue_dir);
void update_review_item(const std::string& queue_dir,
                        const std::string& action_id,
                        const std::string& status,
                        const std::string& decision_note);
std::string replay_review_item(const std::string& queue_dir,
                               const std::string& action_id,
                               const std::string& replay_dir,
                               const std::string& decision_note);
