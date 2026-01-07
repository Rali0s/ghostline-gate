#pragma once
#include "core/types.hpp"
#include <cstdint>

enum class Direction {
    ClientToServer = 0,
    ServerToClient = 1
};

struct Frame {
    uint64_t timestamp_ns;
    uint32_t flow_id;
    Direction dir;
    ByteVec payload;
};