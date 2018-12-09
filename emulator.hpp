#pragma once

#include <net.hpp>

#include <vector>
#include <utility>
#include <chrono>

using host_port = std::pair<std::string,uint16_t>; // <hostname,port>
struct forwarding_entry
{
    host_port emulator;
    host_port destination;
    host_port next_hop;

    std::chrono::milliseconds delay;
    uint8_t loss_probability; // [0,100]
};
using forwarding_table = std::vector<forwarding_entry>;
