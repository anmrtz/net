#include <net.hpp>

#include <boost/program_options.hpp>
#include <boost/lexical_cast.hpp>

#include <iostream>
#include <fstream>
#include <queue>
#include <vector>
#include <chrono>
#include <sstream>
#include <thread>
#include <random>
#include <utility>
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
                forwarding_hop(ee_next_hop_addr, 0, ee.delay, ee.loss_probability)));
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
#ifdef DEBUG_MSG
        stream << "Destination: (" << inet_ntoa(dest_addr->sin_addr) << ',' <<  ntohs(dest_addr->sin_port) << 
            ") --> Next-hop: (" << inet_ntoa(next_hop_addr->sin_addr) << ',' << ntohs(next_hop_addr->sin_port) << ")\n";
#endif
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
using packet_queue = std::queue<TransportPacket>;
static packet_queue outgoing_queue;

static uint8_t random_percent()
{
    static std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 100);

    return dis(gen);
}

static void routing_loop(const forwarding_table & ft, const net::sock_fd & recv_sock_fd, const sockaddr & router_addr,
    const uint32_t queue_max_size)
{
    std::array<uint8_t, net::RECV_BUFFER_SIZE> recv_buf;
    auto packet_wake_time = std::chrono::system_clock::now();
    bool front_packet_being_delayed{false};

    std::cout << "\nStarting routing loop...\n";
#ifdef DEBUG_MSG
    auto emulator_start_time = std::chrono::system_clock::now();
#endif
    while (true)
    {
        std::this_thread::sleep_for(net::RECV_LOOP_DELAY);

        sockaddr src_addr;
        memset(&src_addr, 0, sizeof(src_addr));
        socklen_t src_addr_len{sizeof(src_addr)};

        int recv_len = recvfrom(recv_sock_fd.get(), recv_buf.data(), recv_buf.size(), 0, &src_addr, &src_addr_len);
        // if packet has been received...
        if (recv_len > 0)
        {
            TransportPacket recv_packet(recv_buf.data(), recv_len);

            // Future plans - check if this is a routing packet

            // else try to queue it
            if (outgoing_queue.size() < queue_max_size)
            {
                // first make sure the packet has a valid next-hop for its destination
                const sockaddr packet_dest_addr = recv_packet.get_transport_dest();

                if (ft.count(*(sockaddr_in*)&packet_dest_addr))
                    outgoing_queue.push(std::move(recv_packet));
                else
                    std::cout << "routing_loop event: packet dropped due to no valid next-hop\n";
            }
            else
            {
                std::cout << "routing_loop event: packet dropped due to full queue\n";
            }
        }
        // else if there is a packet being delayed and the delay is over
        else if (front_packet_being_delayed && std::chrono::system_clock::now() > packet_wake_time)
        {
            // get forwarding hop
            const auto & front_packet = outgoing_queue.front();
            const sockaddr front_dest_addr = front_packet.get_transport_dest();
            const auto & forward_hop = ft.at(*(sockaddr_in*)&front_dest_addr);

            const auto drop_chance = forward_hop.loss_probability;
            decltype(drop_chance) roll_percentage{random_percent()};
#ifdef DEBUG_MSG
            const auto send_time = std::chrono::system_clock::now() - emulator_start_time;
            std::cout << "Packet. Type : " 
                << static_cast<std::underlying_type<net::BASE_PACKET_TYPE>::type>(front_packet.get_base_type())
                << "; Orig: " << net::sockaddr_to_str(front_packet.get_transport_src()) 
                << "; Dest: " << net::sockaddr_to_str(front_packet.get_transport_dest())
                << "; Hop: " << net::sockaddr_to_str(*(sockaddr*)&forward_hop.hop_addr)
                << "; Time (ms): " << std::chrono::duration_cast<std::chrono::milliseconds>(send_time).count()
                << "; SN: " << front_packet.get_seq_no();
#endif
            if (roll_percentage >= drop_chance)
            {
                front_packet.forward_packet(recv_sock_fd,*(sockaddr*)&forward_hop.hop_addr);
            }
#ifdef DEBUG_MSG
            else
                std::cout << " - DROPPED";
            std::cout << '\n';
#endif
            outgoing_queue.pop();
            front_packet_being_delayed = false;
        }
        // else retrieve the next packet if there 
        else if (!front_packet_being_delayed && !outgoing_queue.empty())
        {
            const sockaddr front_dest_addr = outgoing_queue.front().get_transport_dest();
            packet_wake_time = std::chrono::system_clock::now() + ft.at(*(sockaddr_in*)&front_dest_addr).delay;
            //std::cout << "Delaying packet (ms): " << std::chrono::duration_cast<std::chrono::milliseconds>(packet_wake_time - std::chrono::system_clock::now()).count();
            front_packet_being_delayed = true;
        }
    }
}

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

    try
    {
        std::fstream et_file(emulator_table_filename);
        if (!et_file.is_open())
        {
            std::cerr << "Could not open forwarding table file: " << emulator_table_filename << '\n';
            return -1;
        }

        const auto recv_fd_addr = net::bind_recv_local(emulator_port);
        auto ft = generate_forwarding_table(parse_emulator_table(et_file),recv_fd_addr.second);
        std::cout << "\nGenerated forwarding table for this node:\n"; print_forwarding_table(ft,std::cout);

        routing_loop(ft,recv_fd_addr.first,recv_fd_addr.second,queue_size);
    }
    catch (std::runtime_error & e)
    {
        std::cerr << "\nError generating forwarding table: " << e.what() << '\n' << std::flush;
        return -1;
    }

    return 0;
}
