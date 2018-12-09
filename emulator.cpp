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

static forwarding_table parse_forwarding_table(std::iostream & stream)
{
    forwarding_table ft;
    std::string line;

    while(std::getline(stream,line))
    {
        using name_t = decltype(host_port::first);
        using port_t = decltype(host_port::second);
        name_t name;
        port_t port;

        forwarding_entry fe;

        std::stringstream ss(line);
        try
        {
            std::string str;
            // get emulator
            ss >> name;
            ss >> str; port = boost::lexical_cast<port_t>(str);
            fe.emulator = std::make_pair(name,port);

            // get destination
            ss >> name;
            ss >> str; port = boost::lexical_cast<port_t>(str);
            fe.destination = std::make_pair(name,port);
            
            // get namehop
            ss >> name;
            ss >> str; port = boost::lexical_cast<port_t>(str);
            fe.next_hop = std::make_pair(name,port);

            // get delay
            ss >> str; fe.delay = decltype(fe.delay)(boost::lexical_cast<uint32_t>(str));

            // get loss probability
            ss >> str; fe.loss_probability = boost::lexical_cast<uint16_t>(str);
        }
        catch (std::exception & e)
        {
            throw std::runtime_error("parse_forwarding_table error. Could not parse line: " + line + "; " + e.what() + "\n");
        }

        ft.emplace_back(std::move(fe));
    }
    return ft;
}

static void print_forwarding_table(const forwarding_table & ft, std::ostream & stream)
{
    for (const auto & fe : ft)
    {
        stream << "Emulator(" << fe.emulator.first << "," << fe.emulator.second << ") ";
        stream << "Destination(" << fe.destination.first << "," << fe.destination.second << ") ";
        stream << "NextHop(" << fe.next_hop.first << "," << fe.next_hop.second << ") ";
        stream << "Delay-ms(" << fe.delay.count() << ") ";
        stream << "Loss-\%(" << uint16_t(fe.loss_probability) << ")\n";
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
    std::string forwarding_table_filename, log_filename;

    {
        po::options_description desc;
        try
        {
            desc.add_options()
                (",p", po::value<decltype(emulator_port)>(&emulator_port)->required(), "emulator port")
                (",q", po::value<decltype(queue_size)>(&queue_size)->required(), "queue size")
                (",f", po::value<decltype(forwarding_table_filename)>(&forwarding_table_filename)->required(), 
                    "forwarding table filename")
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

    std::fstream ft_file(forwarding_table_filename);
    if (!ft_file.is_open())
    {
        std::cerr << "Could not open forwarding table file: " << forwarding_table_filename << '\n';
        return -1;
    }
    try
    {
        auto ft = parse_forwarding_table(ft_file);
        std::cout << "Parsed forwarding table:\n"; print_forwarding_table(ft,std::cout);
    }
    catch (std::exception & e)
    {
        std::cerr << e.what() << '\n' << std::flush;
        std::cout << std::flush;
        return -1;
    }

    return 0;
}
