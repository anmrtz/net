#pragma once

#include <net.hpp>

#include <vector>
#include <utility>
#include <chrono>
#include <map>

using host_port = std::pair<std::string,uint16_t>; // <hostname,port>
struct emulator_entry
{
    host_port emulator;
    host_port destination;
    host_port next_hop;

    std::chrono::milliseconds delay;
    uint8_t loss_probability; // [0,100]
};
using emulator_table = std::vector<emulator_entry>;

struct forwarding_dest
{
    sockaddr dest_addr;
    uint32_t distance;

    std::chrono::milliseconds delay;
    uint8_t loss_probability; // [0,100]

    forwarding_dest(const sockaddr & addr, uint32_t distance_ = 0, 
        const std::chrono::milliseconds & delay_ = std::chrono::milliseconds(0), uint8_t loss_probability_ = 0) :
        dest_addr(addr), distance(distance_), delay(delay_), loss_probability(loss_probability_)
    {}
};
using forwarding_table = std::map<uint32_t, forwarding_dest>; // ip4 destination, gateway emulator; process from forwarding_table
