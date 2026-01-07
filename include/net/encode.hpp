#pragma once
#include "core/types.hpp"
#include <arpa/inet.h>
#include <cstring>

inline ByteVec encode_length_prefixed(const ByteVec& payload) {
    ByteVec out;
    out.reserve(4 + payload.size());

    uint32_t nlen = htonl(static_cast<uint32_t>(payload.size()));
    byte hdr[4];
    std::memcpy(hdr, &nlen, 4);

    out.insert(out.end(), hdr, hdr + 4);
    out.insert(out.end(), payload.begin(), payload.end());
    return out;
}