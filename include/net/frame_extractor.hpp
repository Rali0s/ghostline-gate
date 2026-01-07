#include "net/frame.hpp"
#include "net/stream_buffer.hpp"

class FrameExtractor {
public:
    void push(const byte* p, size_t n) {
        sb_.append(p, n);
    }

    bool has_frame() const {
        uint32_t len;
        if (!sb_.peek_u32(len)) return false;
        return sb_.can_read(4 + len);
    }

    Frame pop(uint64_t ts, uint32_t flow, Direction dir) {
        uint32_t len;
        sb_.peek_u32(len);
        sb_.consume(4);

        Frame f;
        f.timestamp_ns = ts;
        f.flow_id = flow;
        f.dir = dir;
        f.payload = sb_.take(len);
        return f;
    }

private:
    StreamBuffer sb_;
};