#pragma once

#include "transform/transform.hpp"
#include <memory>
#include <vector>

class TransformChain {
public:
    void add(std::unique_ptr<Transform> t) {
        chain_.push_back(std::move(t));
    }

    void apply(Frame& frame) const {
        for (auto& t : chain_)
            t->apply(frame);
    }

private:
    std::vector<std::unique_ptr<Transform>> chain_;
};
