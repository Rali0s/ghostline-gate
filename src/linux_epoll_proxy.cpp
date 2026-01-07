// src/linux_epoll_proxy.cpp
// Linux-first epoll TCP proxy with length-prefixed framing + transform hook.
// Protocol (LAB): [uint32_be length][payload bytes]
//
// Build: this file expects your existing headers:
//   include/core/types.hpp
//   include/net/frame.hpp
//   include/net/stream_buffer.hpp
//   include/net/frame_extractor.hpp
//   include/net/encode.hpp
//   include/transform/transform.hpp
//   include/transform/chain.hpp
//   include/net/proxy.hpp   (ProxyConfig + run_epoll_proxy decl)
//
// Notes:
// - Uses epoll.data.fd everywhere (no ptr/fd mixing).
// - Handles nonblocking upstream connect (EINPROGRESS) correctly.
// - Ensures EPOLLOUT is enabled whenever outq has data.
// - Closes fds with epoll DEL + fdctx cleanup before close().
// - One FrameExtractor per (flow, direction).

#include "net/proxy.hpp"
#include "transform/chain.hpp"

#include "net/frame_extractor.hpp"
#include "net/encode.hpp"
#include "net/frame.hpp"

#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <fcntl.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <cstdio>
#include <cstdlib>

#include <unordered_map>
#include <deque>
#include <chrono>
#include <string>

// ---------- time ----------
static uint64_t now_ns() {
    using namespace std::chrono;
    return duration_cast<nanoseconds>(steady_clock::now().time_since_epoch()).count();
}

// ---------- utils ----------
static std::string last_err() { return std::string(std::strerror(errno)); }

static int set_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) return -1;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

static void close_quiet(int fd) {
    if (fd >= 0) ::close(fd);
}

static uint32_t base_events(bool want_write) {
    uint32_t ev = EPOLLIN | EPOLLRDHUP | EPOLLERR;
    if (want_write) ev |= EPOLLOUT;
    return ev;
}

// ---------- accept/connect ----------
static int create_listen_socket(const std::string& host, uint16_t port) {
    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    addrinfo* res = nullptr;
    char portbuf[16];
    std::snprintf(portbuf, sizeof(portbuf), "%u", port);

    int rc = getaddrinfo(host.c_str(), portbuf, &hints, &res);
    if (rc != 0) {
        std::fprintf(stderr, "getaddrinfo(listen) failed: %s\n", gai_strerror(rc));
        return -1;
    }

    int listen_fd = -1;
    for (addrinfo* p = res; p; p = p->ai_next) {
        int fd = ::socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (fd < 0) continue;

        int yes = 1;
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

        if (::bind(fd, p->ai_addr, p->ai_addrlen) == 0) {
            if (::listen(fd, 256) == 0) {
                listen_fd = fd;
                break;
            }
        }
        close_quiet(fd);
    }

    freeaddrinfo(res);

    if (listen_fd < 0) {
        std::fprintf(stderr, "Failed to bind/listen on %s:%u\n", host.c_str(), port);
        return -1;
    }

    if (set_nonblocking(listen_fd) != 0) {
        std::fprintf(stderr, "Failed to set nonblocking listen fd: %s\n", last_err().c_str());
        close_quiet(listen_fd);
        return -1;
    }

    return listen_fd;
}

static int connect_upstream(const std::string& host, uint16_t port, bool& in_progress) {
    in_progress = false;

    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    addrinfo* res = nullptr;
    char portbuf[16];
    std::snprintf(portbuf, sizeof(portbuf), "%u", port);

    int rc = getaddrinfo(host.c_str(), portbuf, &hints, &res);
    if (rc != 0) {
        std::fprintf(stderr, "getaddrinfo(upstream) failed: %s\n", gai_strerror(rc));
        return -1;
    }

    int fd = -1;
    for (addrinfo* p = res; p; p = p->ai_next) {
        int s = ::socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (s < 0) continue;

        if (set_nonblocking(s) != 0) {
            close_quiet(s);
            continue;
        }

        int c = ::connect(s, p->ai_addr, p->ai_addrlen);
        if (c == 0) {
            fd = s;
            in_progress = false;
            break;
        }
        if (c < 0 && errno == EINPROGRESS) {
            fd = s;
            in_progress = true;
            break;
        }

        close_quiet(s);
    }

    freeaddrinfo(res);
    return fd;
}

// ---------- proxy state ----------
struct Peer {
    int fd = -1;
    bool want_write = false;
    bool connecting = false;          // only relevant for upstream side
    std::deque<ByteVec> outq;         // queued encoded frames
};

struct Flow {
    uint32_t id = 0;
    Peer client;
    Peer upstream;
    bool closed = false;
};

struct FdCtx {
    uint32_t flow_id;
    bool is_client; // true => client socket, false => upstream socket
};

// ---------- framing bridge (per-flow, per-direction) ----------
static std::unordered_map<uint64_t, FrameExtractor> g_extractors;

static inline uint64_t extractor_key(uint32_t flow, Direction dir) {
    return (uint64_t(flow) << 1) | (dir == Direction::ServerToClient ? 1ULL : 0ULL);
}

static void process_chunk_to_outq(
    uint32_t flow_id,
    Direction dir,
    const byte* data,
    size_t len,
    uint64_t ts,
    TransformChain& chain,
    std::deque<ByteVec>& outq
) {
    auto& ex = g_extractors[extractor_key(flow_id, dir)];
    ex.push(data, len);

    while (ex.has_frame()) {
        Frame f = ex.pop(ts, flow_id, dir);

        // semantic modification point
        chain.apply(f);

        // re-encode and queue
        if (!f.payload.empty()) {
            outq.push_back(encode_length_prefixed(f.payload));
        }
    }
}

// ---------- write flushing ----------
static bool flush_outq(int fd, std::deque<ByteVec>& outq) {
    while (!outq.empty()) {
        ByteVec& front = outq.front();
        if (front.empty()) { outq.pop_front(); continue; }

        ssize_t n = ::send(fd, front.data(), front.size(), MSG_NOSIGNAL);
        if (n > 0) {
            front.erase(front.begin(), front.begin() + n);
            if (!front.empty()) return true; // still pending
            outq.pop_front();
            continue;
        }

        if (n < 0 && (errno == EWOULDBLOCK || errno == EAGAIN)) {
            return true; // pending; need EPOLLOUT
        }

        // fatal send error / disconnect
        return false;
    }
    return false; // nothing pending
}

// ---------- close with cleanup ----------
static void close_flow(
    int ep,
    std::unordered_map<int, FdCtx>& fdctx,
    std::unordered_map<uint32_t, Flow>& flows,
    uint32_t flow_id
) {
    auto it = flows.find(flow_id);
    if (it == flows.end()) return;
    Flow& f = it->second;
    if (f.closed) return;
    f.closed = true;

    int cfd = f.client.fd;
    int sfd = f.upstream.fd;

    if (cfd >= 0) {
        epoll_ctl(ep, EPOLL_CTL_DEL, cfd, nullptr);
        fdctx.erase(cfd);
        close_quiet(cfd);
    }
    if (sfd >= 0) {
        epoll_ctl(ep, EPOLL_CTL_DEL, sfd, nullptr);
        fdctx.erase(sfd);
        close_quiet(sfd);
    }

    f.client.fd = -1;
    f.upstream.fd = -1;

    // optional: drop extractors for this flow to avoid memory growth
    g_extractors.erase(extractor_key(flow_id, Direction::ClientToServer));
    g_extractors.erase(extractor_key(flow_id, Direction::ServerToClient));

    flows.erase(it);
}

// ---------- main ----------
int run_epoll_proxy(const ProxyConfig& cfg, TransformChain& chain) {
    int listen_fd = create_listen_socket(cfg.listen_host, cfg.listen_port);
    if (listen_fd < 0) return 1;

    int ep = epoll_create1(0);
    if (ep < 0) {
        std::fprintf(stderr, "epoll_create1 failed: %s\n", last_err().c_str());
        close_quiet(listen_fd);
        return 1;
    }

    // register listen fd using data.fd
    {
        epoll_event ev{};
        ev.events = EPOLLIN | EPOLLERR;
        ev.data.fd = listen_fd;
        if (epoll_ctl(ep, EPOLL_CTL_ADD, listen_fd, &ev) != 0) {
            std::fprintf(stderr, "epoll ADD listen failed: %s\n", last_err().c_str());
            close_quiet(listen_fd);
            close_quiet(ep);
            return 1;
        }
    }

    std::unordered_map<uint32_t, Flow> flows;
    std::unordered_map<int, FdCtx> fdctx;
    uint32_t next_flow_id = 1;

    ByteVec readbuf(cfg.max_chunk);

    const int MAX_EVENTS = 64;
    epoll_event events[MAX_EVENTS];

    while (true) {
        int n = epoll_wait(ep, events, MAX_EVENTS, -1);
        if (n < 0) {
            if (errno == EINTR) continue;
            std::fprintf(stderr, "epoll_wait failed: %s\n", last_err().c_str());
            break;
        }

        for (int i = 0; i < n; ++i) {
            int fd = events[i].data.fd;
            uint32_t ev = events[i].events;

            // ---- listen accept ----
            if (fd == listen_fd) {
                if (ev & (EPOLLERR | EPOLLHUP)) {
                    std::fprintf(stderr, "listen fd error/hup\n");
                    continue;
                }

                while (true) {
                    sockaddr_storage ss{};
                    socklen_t slen = sizeof(ss);
                    int cfd = ::accept(listen_fd, (sockaddr*)&ss, &slen);
                    if (cfd < 0) {
                        if (errno == EAGAIN || errno == EWOULDBLOCK) break;
                        std::fprintf(stderr, "accept failed: %s\n", last_err().c_str());
                        break;
                    }

                    if (set_nonblocking(cfd) != 0) {
                        std::fprintf(stderr, "set_nonblocking(client) failed: %s\n", last_err().c_str());
                        close_quiet(cfd);
                        continue;
                    }

                    bool inprog = false;
                    int sfd = connect_upstream(cfg.upstream_host, cfg.upstream_port, inprog);
                    if (sfd < 0) {
                        std::fprintf(stderr, "connect_upstream failed\n");
                        close_quiet(cfd);
                        continue;
                    }

                    uint32_t fid = next_flow_id++;

                    Flow flow;
                    flow.id = fid;
                    flow.client.fd = cfd;
                    flow.upstream.fd = sfd;
                    flow.upstream.connecting = inprog;

                    flows.emplace(fid, std::move(flow));

                    fdctx[cfd] = FdCtx{fid, true};
                    fdctx[sfd] = FdCtx{fid, false};

                    // add client fd
                    {
                        epoll_event evc{};
                        evc.events = base_events(false);
                        evc.data.fd = cfd;
                        epoll_ctl(ep, EPOLL_CTL_ADD, cfd, &evc);
                    }

                    // add upstream fd - if connecting, we need EPOLLOUT to complete connect
                    {
                        epoll_event evs{};
                        bool want_write = inprog; // EPOLLOUT to finish connect
                        evs.events = base_events(want_write);
                        evs.data.fd = sfd;
                        epoll_ctl(ep, EPOLL_CTL_ADD, sfd, &evs);

                        auto itf = flows.find(fid);
                        if (itf != flows.end()) itf->second.upstream.want_write = want_write;
                    }

                    std::fprintf(stderr, "[flow %u] client fd=%d upstream fd=%d (connecting=%s)\n",
                                 fid, cfd, sfd, inprog ? "yes" : "no");
                }

                continue;
            }

            // ---- peer event ----
            auto itctx = fdctx.find(fd);
            if (itctx == fdctx.end()) {
                // unknown fd (could be a late event after cleanup)
                continue;
            }

            FdCtx ctx = itctx->second;
            auto itf = flows.find(ctx.flow_id);
            if (itf == flows.end()) continue;

            Flow& f = itf->second;
            Peer& src = ctx.is_client ? f.client : f.upstream;
            Peer& dst = ctx.is_client ? f.upstream : f.client;

            // close on hangup/error
            if (ev & (EPOLLERR | EPOLLRDHUP | EPOLLHUP)) {
                std::fprintf(stderr, "[flow %u] fd=%d close/err\n", f.id, fd);
                close_flow(ep, fdctx, flows, f.id);
                continue;
            }

            // ---- writable ----
            if (ev & EPOLLOUT) {
                // complete nonblocking connect if this is upstream and connecting
                if (!ctx.is_client && src.connecting) {
                    int err = 0;
                    socklen_t elen = sizeof(err);
                    if (getsockopt(src.fd, SOL_SOCKET, SO_ERROR, &err, &elen) != 0 || err != 0) {
                        std::fprintf(stderr, "[flow %u] upstream connect failed: %s\n",
                                     f.id, (err != 0 ? std::strerror(err) : last_err().c_str()));
                        close_flow(ep, fdctx, flows, f.id);
                        continue;
                    }
                    src.connecting = false;
                    // keep EPOLLOUT only if there is queued data
                    src.want_write = !src.outq.empty();
                    epoll_event mod{};
                    mod.events = base_events(src.want_write);
                    mod.data.fd = src.fd;
                    epoll_ctl(ep, EPOLL_CTL_MOD, src.fd, &mod);
                }

                // flush queued writes
                if (!src.outq.empty()) {
                    bool still_pending = flush_outq(src.fd, src.outq);
                    src.want_write = still_pending;

                    epoll_event mod{};
                    mod.events = base_events(src.want_write || src.connecting);
                    mod.data.fd = src.fd;
                    epoll_ctl(ep, EPOLL_CTL_MOD, src.fd, &mod);
                } else {
                    // nothing queued; turn off EPOLLOUT unless connecting
                    if (src.want_write && !src.connecting) {
                        src.want_write = false;
                        epoll_event mod{};
                        mod.events = base_events(false);
                        mod.data.fd = src.fd;
                        epoll_ctl(ep, EPOLL_CTL_MOD, src.fd, &mod);
                    }
                }
            }

            // ---- readable ----
            if (ev & EPOLLIN) {
                // If upstream is still connecting, don't attempt recv/send yet.
                if (!ctx.is_client && src.connecting) {
                    continue;
                }

                while (true) {
                    ssize_t r = ::recv(src.fd, readbuf.data(), readbuf.size(), 0);
                    if (r > 0) {
                        Direction dir = ctx.is_client ? Direction::ClientToServer : Direction::ServerToClient;

                        // bridge: chunk -> frames -> transform -> encoded -> dst.outq
                        process_chunk_to_outq(
                            f.id,
                            dir,
                            readbuf.data(),
                            static_cast<size_t>(r),
                            now_ns(),
                            chain,
                            dst.outq
                        );

                        // ensure EPOLLOUT on dst if we queued anything
                        if (!dst.outq.empty() && !dst.want_write) {
                            dst.want_write = true;
                            epoll_event mod{};
                            mod.events = base_events(true || dst.connecting);
                            mod.data.fd = dst.fd;
                            epoll_ctl(ep, EPOLL_CTL_MOD, dst.fd, &mod);
                        }

                        continue;
                    }

                    if (r == 0) {
                        std::fprintf(stderr, "[flow %u] fd=%d EOF\n", f.id, src.fd);
                        close_flow(ep, fdctx, flows, f.id);
                        break;
                    }

                    if (errno == EWOULDBLOCK || errno == EAGAIN) {
                        break;
                    }

                    std::fprintf(stderr, "[flow %u] recv error: %s\n", f.id, last_err().c_str());
                    close_flow(ep, fdctx, flows, f.id);
                    break;
                }
            }
        }
    }

    close_quiet(listen_fd);
    close_quiet(ep);
    return 1;
}

