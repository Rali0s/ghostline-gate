#pragma once

#include <cstdint>
#include <string>
#include <vector>

struct TcpSocketEntry {
    std::string file_descriptor;
    std::string address_family;
    std::string endpoint;
    std::string state;
    std::int32_t local_port = -1;
    std::int32_t remote_port = -1;
    bool has_remote = false;
    bool is_listen = false;
};

struct ProcessSocketEntry {
    std::int64_t pid = -1;
    std::string command;
    std::string user;
    std::vector<TcpSocketEntry> sockets;
};

struct PidSearchQuery {
    std::string process_contains;
    std::int64_t pid = -1;
    std::int32_t port = -1;
    std::string state;
    bool listen_only = false;
    bool established_only = false;
};

std::vector<ProcessSocketEntry> parse_lsof_tcp_listing(const std::string& text);
std::vector<ProcessSocketEntry> filter_process_sockets(const std::vector<ProcessSocketEntry>& entries,
                                                       const PidSearchQuery& query);
std::vector<ProcessSocketEntry> query_tcp_processes(const PidSearchQuery& query);
std::string process_sockets_to_json(const std::vector<ProcessSocketEntry>& entries);
