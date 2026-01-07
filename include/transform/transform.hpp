#pragma once
#include "net/frame.hpp"

class Transform {
public:	
	virtual ~Transform() = default;
	virtual void apply(Frame& frame) = 0;
};