#include "ghostline/pid_search.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdio>
#include <memory>
#include <sstream>
#include <stdexcept>

namespace {

std::string trim_copy(std::string value) {
    while (!value.empty() && (value.back() == '\n' || value.back() == '\r')) {
        value.pop_back();
    }
    return value;
}

std::string lowercase_copy(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char ch) {
        return static_cast<char>(std::tolower(ch));
    });
    return value;
}

std::string json_escape(const std::string& value) {
    std::string escaped;
    escaped.reserve(value.size() + 8);
    for (char ch : value) {
        switch (ch) {
        case '\\': escaped += "\\\\"; break;
        case '"': escaped += "\\\""; break;
        case '\n': escaped += "\\n"; break;
        case '\r': escaped += "\\r"; break;
        case '\t': escaped += "\\t"; break;
        default: escaped.push_back(ch); break;
        }
    }
    return escaped;
}

std::int32_t parse_port_tail(const std::string& segment) {
    const std::size_t colon = segment.rfind(':');
    if (colon == std::string::npos || colon + 1 >= segment.size()) {
        return -1;
    }
    const std::string port_text = segment.substr(colon + 1);
    if (port_text.empty() || !std::all_of(port_text.begin(), port_text.end(), ::isdigit)) {
        return -1;
    }
    return static_cast<std::int32_t>(std::stoi(port_text));
}

void hydrate_endpoint(TcpSocketEntry& socket) {
    if (socket.endpoint.empty()) {
        return;
    }

    const std::size_t arrow = socket.endpoint.find("->");
    if (arrow == std::string::npos) {
        socket.local_port = parse_port_tail(socket.endpoint);
        socket.remote_port = -1;
        socket.has_remote = false;
    } else {
        const std::string local = socket.endpoint.substr(0, arrow);
        const std::string remote = socket.endpoint.substr(arrow + 2);
        socket.local_port = parse_port_tail(local);
        socket.remote_port = parse_port_tail(remote);
        socket.has_remote = socket.remote_port >= 0;
    }

    socket.is_listen = socket.state == "LISTEN";
}

bool entry_matches_process(const ProcessSocketEntry& entry, const PidSearchQuery& query) {
    if (query.pid >= 0 && entry.pid != query.pid) {
        return false;
    }

    if (!query.process_contains.empty()) {
        const std::string needle = lowercase_copy(query.process_contains);
        const std::string command = lowercase_copy(entry.command);
        const std::string pid_text = std::to_string(entry.pid);
        if (command.find(needle) == std::string::npos && pid_text.find(needle) == std::string::npos) {
            return false;
        }
    }

    return true;
}

bool socket_matches(const TcpSocketEntry& socket, const PidSearchQuery& query) {
    if (query.port >= 0 && socket.local_port != query.port && socket.remote_port != query.port) {
        return false;
    }

    if (!query.state.empty() && lowercase_copy(socket.state) != lowercase_copy(query.state)) {
        return false;
    }

    if (query.listen_only && !socket.is_listen) {
        return false;
    }

    if (query.established_only && socket.state != "ESTABLISHED") {
        return false;
    }

    return true;
}

std::string run_command_capture(const std::string& command) {
    std::array<char, 4096> buffer{};
    std::string output;

    std::unique_ptr<FILE, decltype(&pclose)> handle(popen(command.c_str(), "r"), pclose);
    if (!handle) {
        throw std::runtime_error("failed to start lsof");
    }

    while (fgets(buffer.data(), static_cast<int>(buffer.size()), handle.get()) != nullptr) {
        output.append(buffer.data());
    }

    const int status = pclose(handle.release());
    if (status != 0 && output.empty()) {
        throw std::runtime_error("lsof did not return any data");
    }

    return output;
}

} // namespace

std::vector<ProcessSocketEntry> parse_lsof_tcp_listing(const std::string& text) {
    std::vector<ProcessSocketEntry> processes;
    ProcessSocketEntry* current_process = nullptr;
    TcpSocketEntry* current_socket = nullptr;

    std::istringstream stream(text);
    std::string line;
    while (std::getline(stream, line)) {
        line = trim_copy(line);
        if (line.empty()) {
            continue;
        }

        const char field = line.front();
        const std::string value = line.substr(1);

        switch (field) {
        case 'p': {
            processes.push_back({});
            current_process = &processes.back();
            current_process->pid = std::stoll(value);
            current_socket = nullptr;
            break;
        }
        case 'c':
            if (current_process != nullptr) current_process->command = value;
            break;
        case 'u':
            if (current_process != nullptr) current_process->user = value;
            break;
        case 'f':
            if (current_process != nullptr) {
                current_process->sockets.push_back({});
                current_socket = &current_process->sockets.back();
                current_socket->file_descriptor = value;
            }
            break;
        case 't':
            if (current_socket != nullptr) current_socket->address_family = value;
            break;
        case 'n':
            if (current_socket != nullptr) current_socket->endpoint = value;
            break;
        case 'T':
            if (current_socket != nullptr && value.rfind("ST=", 0) == 0) {
                current_socket->state = value.substr(3);
            }
            break;
        default:
            break;
        }
    }

    for (auto& process : processes) {
        for (auto& socket : process.sockets) {
            hydrate_endpoint(socket);
        }
    }

    return processes;
}

std::vector<ProcessSocketEntry> filter_process_sockets(const std::vector<ProcessSocketEntry>& entries,
                                                       const PidSearchQuery& query) {
    std::vector<ProcessSocketEntry> filtered;
    for (const auto& entry : entries) {
        if (!entry_matches_process(entry, query)) {
            continue;
        }

        ProcessSocketEntry process = entry;
        process.sockets.clear();
        for (const auto& socket : entry.sockets) {
            if (socket_matches(socket, query)) {
                process.sockets.push_back(socket);
            }
        }

        if (query.port >= 0 || !query.state.empty() || query.listen_only || query.established_only) {
            if (!process.sockets.empty()) {
                filtered.push_back(std::move(process));
            }
        } else {
            filtered.push_back(std::move(process));
        }
    }

    return filtered;
}

std::vector<ProcessSocketEntry> query_tcp_processes(const PidSearchQuery& query) {
    const std::string output = run_command_capture("lsof -nP -FpcuftnT -iTCP");
    return filter_process_sockets(parse_lsof_tcp_listing(output), query);
}

std::string process_sockets_to_json(const std::vector<ProcessSocketEntry>& entries) {
    std::ostringstream out;
    out << "{\n  \"processes\": [";
    for (std::size_t i = 0; i < entries.size(); ++i) {
        const auto& process = entries[i];
        if (i != 0) out << ",";
        out << "\n    {"
            << "\"pid\": " << process.pid
            << ", \"command\": \"" << json_escape(process.command) << "\""
            << ", \"user\": \"" << json_escape(process.user) << "\""
            << ", \"sockets\": [";
        for (std::size_t j = 0; j < process.sockets.size(); ++j) {
            const auto& socket = process.sockets[j];
            if (j != 0) out << ",";
            out << "\n      {"
                << "\"fd\": \"" << json_escape(socket.file_descriptor) << "\""
                << ", \"family\": \"" << json_escape(socket.address_family) << "\""
                << ", \"endpoint\": \"" << json_escape(socket.endpoint) << "\""
                << ", \"state\": \"" << json_escape(socket.state) << "\""
                << ", \"local_port\": " << socket.local_port
                << ", \"remote_port\": " << socket.remote_port
                << ", \"has_remote\": " << (socket.has_remote ? "true" : "false")
                << ", \"is_listen\": " << (socket.is_listen ? "true" : "false")
                << "}";
        }
        out << "\n    ]}";
    }
    out << "\n  ]\n}\n";
    return out.str();
}
