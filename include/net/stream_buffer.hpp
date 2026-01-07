#pragma once

#include "core/types.hpp"
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <arpa/inet.h>

/*
 * StreamBuffer
 *
 * Purpose:
 *  - Accumulate arbitrary TCP stream bytes
 *  - Support peeking / consuming without corruption
 *  - Used ONLY between recv() and FrameExtractor
 *
 * Invariants:
 *  - Data is always in network byte order
 *  - No framing logic here (that belongs in FrameExtractor)
 */

class StreamBuffer {
public:
    StreamBuffer() = default;

    // Append raw bytes from recv()
    void append(const byte* data, size_t len) {
        buf_.insert(buf_.end(), data, data + len);
    }

    // Current buffered byte count
    size_t size() const {
        return buf_.size();
    }

    // Peek a network-order uint32 without consuming
    bool peek_u32(uint32_t& out) const {
        if (buf_.size() < sizeof(uint32_t))
            return false;

        uint32_t tmp;
        std::memcpy(&tmp, buf_.data(), sizeof(uint32_t));
        out = ntohl(tmp);
        return true;
    }

    // Check if N bytes are available
    bool can_read(size_t n) const {
        return buf_.size() >= n;
    }

    // Consume N bytes (caller must ensure availability)
    void consume(size_t n) {
        buf_.erase(buf_.begin(), buf_.begin() + n);
    }

    // Take N bytes and consume them
    ByteVec take(size_t n) {
        ByteVec out(buf_.begin(), buf_.begin() + n);
        consume(n);
        return out;
    }

    // Clear buffer completely
    void clear() {
        buf_.clear();
    }

private:
    ByteVec buf_;
};

