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

struct forwarding_hop
{
    sockaddr_in hop_addr;
    uint32_t distance;

    std::chrono::milliseconds delay;
    uint8_t loss_probability; // [0,100]

    forwarding_hop(const sockaddr_in & addr, uint32_t distance_ = 0, 
        const std::chrono::milliseconds & delay_ = std::chrono::milliseconds(0), uint8_t loss_probability_ = 0) :
        hop_addr(addr), distance(distance_), delay(delay_), loss_probability(loss_probability_)
    {}
};

bool operator==(const sockaddr_in & left, const sockaddr_in & right)
{
    return left.sin_family == right.sin_family &&
        left.sin_addr.s_addr == right.sin_addr.s_addr &&
        left.sin_port == right.sin_port;
}
const auto sockaddr_in_comp = [](const sockaddr_in & left, const sockaddr_in & right) -> bool
{
    if (left.sin_addr.s_addr < right.sin_addr.s_addr)
        return true;
    else if (left.sin_addr.s_addr == right.sin_addr.s_addr)
        if (left.sin_port < right.sin_port)
            return true;
    return false;
};
using forwarding_table = std::map<sockaddr_in, forwarding_hop, decltype(sockaddr_in_comp)>; // destination, gateway emulator; process from forwarding_table
