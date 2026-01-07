#pragma once
#include "transform/chain.hpp"
#include <string>
#include <cstdint>
#include <cstddef>

struct ProxyConfig {
    std::string listen_host = "0.0.0.0";
    uint16_t listen_port = 7777;

    std::string upstream_host = "127.0.0.1";
    uint16_t upstream_port = 8888;

    std::size_t max_chunk = 64 * 1024;
};

int run_epoll_proxy(const ProxyConfig& cfg, TransformChain& chain);