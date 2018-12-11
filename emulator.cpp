#include "emulator.hpp"

#include <boost/program_options.hpp>
#include <boost/lexical_cast.hpp>

#include <iostream>
#include <fstream>
#include <queue>
#include <vector>
#include <chrono>
#include <sstream>

namespace po = boost::program_options;
using TransportPacket = net::TransportPacket;
using TRANSPORT_PRIORITY = TransportPacket::TRANSPORT_PRIORITY;

static emulator_table parse_emulator_table(std::iostream & stream)
{
    emulator_table et;
    std::string line;

    while(std::getline(stream,line))
    {
        using name_t = decltype(host_port::first);
        using port_t = decltype(host_port::second);
        name_t name;
        port_t port;

        emulator_entry ee;

        std::stringstream ss(line);
        try
        {
            std::string str;
            // get emulator
            ss >> name;
            ss >> str; port = boost::lexical_cast<port_t>(str);
            ee.emulator = std::make_pair(name,port);

            // get destination
            ss >> name;
            ss >> str; port = boost::lexical_cast<port_t>(str);
            ee.destination = std::make_pair(name,port);
            
            // get namehop
            ss >> name;
            ss >> str; port = boost::lexical_cast<port_t>(str);
            ee.next_hop = std::make_pair(name,port);

            // get delay
            ss >> str; ee.delay = decltype(ee.delay)(boost::lexical_cast<uint32_t>(str));

            // get loss probability
            ss >> str; ee.loss_probability = boost::lexical_cast<uint16_t>(str);
        }
        catch (std::exception & e)
        {
            throw std::runtime_error("parse_forwarding_table error. Could not parse line: " + line + "; " + e.what() + "\n");
        }

        et.emplace_back(std::move(ee));
    }
    return et;
}

static void print_emulator_table(const emulator_table & ft, std::ostream & stream)
{
    for (const auto & ee : ft)
    {
        stream << "Emulator(" << ee.emulator.first << "," << ee.emulator.second << ") ";
        stream << "Destination(" << ee.destination.first << "," << ee.destination.second << ") ";
        stream << "NextHop(" << ee.next_hop.first << "," << ee.next_hop.second << ") ";
        stream << "Delay-ms(" << ee.delay.count() << ") ";
        stream << "Loss-\%(" << +ee.loss_probability << ")\n";
    }
}

static forwarding_table generate_forwarding_table(const emulator_table & et, const sockaddr & machine_addr)
{
    forwarding_table ft(sockaddr_in_comp);

    const sockaddr_in * machine_addr_in = (sockaddr_in*)&machine_addr;

    for (const auto & ee : et)
    {
        // if the ports don't match, then the emulator entry definitely doesn't apply
        if (machine_addr_in->sin_port != htons(ee.emulator.second))
            continue;

        // get emulator entry ip4 emulator address from the hostname
        sockaddr_in ee_emulator_addr, ee_destination_addr, ee_next_hop_addr;
        try
        {
            ee_emulator_addr = net::get_sockaddr_in_from_hostport(ee.emulator.first,ee.emulator.second);
            ee_destination_addr = net::get_sockaddr_in_from_hostport(ee.destination.first,ee.destination.second);
            ee_next_hop_addr = net::get_sockaddr_in_from_hostport(ee.next_hop.first,ee.next_hop.second);
        }
        catch (std::runtime_error & e)
        {
            std::cerr << e.what();
            continue;
        }

        if (*machine_addr_in == ee_emulator_addr)
        {
            // duplicate destination/next-hop pairs are considered an error
            if(ft.count(ee_destination_addr))
                throw std::runtime_error("generate_forwarding_table error: duplicate entries for destination host - "
                    + ee.destination.first + '\n');

            if (*machine_addr_in == ee_next_hop_addr)
                throw std::runtime_error("forwarding table error: circular route - destination(ip,port) == next-hop(ip,port)\n");

            // delay value is unused for now
            ft.insert(std::make_pair(ee_destination_addr, 
                forwarding_dest(ee_next_hop_addr, 0, ee.delay, ee.loss_probability)));
        }
    }

    return ft;
}

static void print_forwarding_table(const forwarding_table & ft, std::ostream & stream)
{
    for (const auto & fe : ft)
    {
        sockaddr_in * dest_addr = (sockaddr_in*)&fe.first;
        sockaddr_in * next_hop_addr = (sockaddr_in*)&fe.second;
        stream << "Destination: (" << inet_ntoa(dest_addr->sin_addr) << ',' <<  ntohs(dest_addr->sin_port) << 
            ") --> Next-hop: (" << inet_ntoa(next_hop_addr->sin_addr) << ',' << ntohs(next_hop_addr->sin_port) << ")\n";
    }
}

static const auto tp_left_priority_less_than = [](const TransportPacket & left, const TransportPacket & right) -> bool
{
    if (left.get_priority() == TRANSPORT_PRIORITY::LOW && right.get_priority() != TRANSPORT_PRIORITY::LOW)
        return true;
    else if (left.get_priority() == TRANSPORT_PRIORITY::MEDIUM && right.get_priority() == TRANSPORT_PRIORITY::HIGH)
        return true;
    else
        return false;
};
using packet_queue = std::priority_queue<TransportPacket, std::vector<TransportPacket>, 
    decltype(tp_left_priority_less_than)>;
static packet_queue outgoing_queue(tp_left_priority_less_than);

int main(int argc, char * argv[])
{
    uint16_t emulator_port, queue_size;
    std::string emulator_table_filename, log_filename;

    {
        po::options_description desc;
        try
        {
            desc.add_options()
                (",p", po::value<decltype(emulator_port)>(&emulator_port)->required(), "emulator port")
                (",q", po::value<decltype(queue_size)>(&queue_size)->required(), "queue size")
                (",f", po::value<decltype(emulator_table_filename)>(&emulator_table_filename)->required(), 
                    "emulator table filename")
                (",l", po::value<decltype(log_filename)>(&log_filename)->required(), "log filename");

            po::variables_map vm;

            po::store(po::parse_command_line(argc,argv,desc), vm);
            po::notify(vm);
        }
        catch (po::error& e)
        {
            std::cerr << "Option parse error: " << e.what() << '\n' << desc << '\n';
            return -1;
        }
    }

    if (emulator_port < 1024 || queue_size < 3)
    {
        std::cerr << "Emulator port must be >= 1024 and queue size must be >= 3\n";
        return -1;
    }

    std::fstream et_file(emulator_table_filename);
    if (!et_file.is_open())
    {
        std::cerr << "Could not open forwarding table file: " << emulator_table_filename << '\n';
        return -1;
    }

    auto recv_fd_addr = net::bind_recv_local(emulator_port);
    const auto & recv_sock_fd = recv_fd_addr.first;
    const auto & emulator_addr = recv_fd_addr.second;
    try
    {
        auto et = parse_emulator_table(et_file);
        std::cout << "\nParsed emulator table:\n"; print_emulator_table(et,std::cout);
        auto ft = generate_forwarding_table(et,emulator_addr);
        std::cout << "\nGenerated forwarding table for this node:\n"; print_forwarding_table(ft,std::cout);
    }
    catch (std::runtime_error & e)
    {
        std::cerr << "\nError generating forwarding table: " << e.what() << '\n' << std::flush;
        return -1;
    }

    return 0;
}
