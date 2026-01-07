#include "net/proxy.hpp"
#include "transform/chain.hpp"
#include <iostream>
#include <cstdlib>

static uint16_t to_u16(const char* s) {
	long v = std::strtol(s, nullptr, 10);
	if (v <1 || v > 65535) throw std::runtime_error("port out of range");
	return static_cast<uint16_t>(v);
}

int main(int argc, char** argv){
	// Usage:
	// ./packetlab_proxy <listen_port> <upstream_host> <upstream_port>

	ProxyConfig cfg;

	try {
		if (argc >= 2) cfg.listen_port = to_u16(argv[1]);
		if (argc >= 3) cfg.upstream_host = argv[2];
		if (argc >= 4) cfg.upstream_port = to_u16(argv[3]);
	} catch (const std::exception& e) {
		std::cerr << "Arg error: " << e.what() << "\n";
		std::cerr << "Usage: " << argv[0] << " [Listenport] [upstream_host] [upstream_port]\n";
		return 2;
	} 

	TransformChain chain;
	// Add tramsforms later:
	// chain.add(std::unique_ptr<Transform>(new YourTransform()))

	std::cout << "Listening on " << cfg.listen_host << ":" << cfg.listen_port
			  << " -> Upstream " << cfg.upstream_host << ":" << cfg.upstream_port << "\n";

	return run_epoll_proxy(cfg, chain);
 }