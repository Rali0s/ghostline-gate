pragma once
#include "transform/transform.hpp"

class PatchTransform : public Transform {
public:
    void apply(Frame& frame) override {
        // demo: uppercase ASCII
        for (auto& b : frame.payload) {
            if (b >= 'a' && b <= 'z')
                b = b - 32;
        }
    }
};