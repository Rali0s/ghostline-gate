#include "ghostline/plugin.hpp"

#include <memory>

std::vector<std::unique_ptr<ProtocolPlugin>> make_builtin_plugins(const MutationConfig& config);

PluginRegistry::PluginRegistry(const MutationConfig& config) : plugins_(make_builtin_plugins(config)) {}

const ProtocolPlugin* PluginRegistry::find_by_name(const std::string& name) const {
    for (std::vector<std::unique_ptr<ProtocolPlugin>>::const_iterator it = plugins_.begin(); it != plugins_.end(); ++it) {
        if ((*it)->name() == name) return it->get();
    }
    return nullptr;
}

const ProtocolPlugin* PluginRegistry::match(const FlowContext& flow, Direction direction, std::uint16_t upstream_port, const ByteVec& buffer) const {
    if (!flow.preferred_plugin.empty()) {
        const ProtocolPlugin* preferred = find_by_name(flow.preferred_plugin);
        if (preferred != nullptr) return preferred;
    }

    for (std::vector<std::unique_ptr<ProtocolPlugin>>::const_iterator it = plugins_.begin(); it != plugins_.end(); ++it) {
        if ((*it)->matches(flow, direction, upstream_port, buffer)) {
            return it->get();
        }
    }
    return nullptr;
}
