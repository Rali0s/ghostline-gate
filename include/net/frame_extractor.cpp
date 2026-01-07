#include "net/frame_extractor.hpp"
#include <arpa/inet.h>
#include <cstring>

bool FrameExtractor::push_bytes(const byte* data, size_t len) {
    buffer_.append(data, len);
    return true;
}

bool FrameExtractor::has_frame() const {
    ByteVec hdr;
    if (!buffer_.peek_bytes(hdr, 4)) return false;

    uint32_t netlen;
    std::memcpy(&netlen, hdr.data(), 4);
    uint32_t len = ntohl(netlen);

    return buffer_.size() >= (4 + len);
}

Frame FrameExtractor::pop_frame(uint64_t ts, uint32_t flow, Direction dir) {
    ByteVec hdr;
    buffer_.read_bytes(hdr, 4);

    uint32_t netlen;
    std::memcpy(&netlen, hdr.data(), 4);
    uint32_t len = ntohl(netlen);

    ByteVec payload;
    buffer_.read_bytes(payload, len);

    Frame f;
    f.timestamp_ns = ts;
    f.flow_id = flow;
    f.dir = dir;
    f.payload = std::move(payload);
    return f;
}