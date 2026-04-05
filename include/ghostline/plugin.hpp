#pragma once

#include "ghostline/model.hpp"
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

struct WindowRule {
    ByteVec start_marker;
    ByteVec end_marker;
    bool rewrite_u32_prefix = false;
};

struct MutationConfig {
    ByteVec start_marker;
    ByteVec end_marker;
    std::string replacement_text;
    std::string raw_find_text;
    bool allow_size_mutation = true;
    bool rewrite_u32_prefix = false;
    bool raw_live_mode = false;
    std::size_t raw_chunk_bytes = 1024;
    bool mutate_client_to_server = true;
    bool mutate_server_to_client = true;
    std::size_t raw_review_threshold_bytes = 0;
    std::size_t mqtt_review_threshold_bytes = 0;
    std::size_t byte_window_review_threshold_bytes = 0;
};

enum class FramingDisposition {
    PassThrough,
    NeedMoreBytes,
    FramedPacket,
    FramingFailed,
};

struct FramingResult {
    FramingDisposition disposition = FramingDisposition::PassThrough;
    ByteVec frame_bytes;
    std::size_t consumed_bytes = 0;
    std::string packet_type;
    std::string detail;
    bool candidate_mutation_allowed = false;
    bool structural_risk = false;
};

class ProtocolPlugin {
public:
    virtual ~ProtocolPlugin() = default;

    virtual std::string name() const = 0;
    virtual bool matches(const FlowContext& flow, Direction direction, std::uint16_t upstream_port, const ByteVec& buffer) const = 0;
    virtual bool uses_protocol_framing() const { return false; }
    virtual FramingResult frame(const FlowContext&, Direction, const ByteVec&) const { return FramingResult(); }
    virtual bool configure_window(const FlowContext& flow, Direction direction, WindowRule& rule) const = 0;
    virtual Candidate build_candidate(const FlowContext& flow, Direction direction, const ByteVec& window, const FramingResult* framed = nullptr) const = 0;
    virtual CandidateDecision decide(const FlowContext& flow, Direction direction, Candidate& candidate) const = 0;
    virtual std::string audit_label() const = 0;
};

class PluginRegistry {
public:
    explicit PluginRegistry(const MutationConfig& config);

    const ProtocolPlugin* match(const FlowContext& flow, Direction direction, std::uint16_t upstream_port, const ByteVec& buffer) const;
    const ProtocolPlugin* find_by_name(const std::string& name) const;
    const std::vector<std::unique_ptr<ProtocolPlugin>>& plugins() const { return plugins_; }

private:
    std::vector<std::unique_ptr<ProtocolPlugin>> plugins_;
};
