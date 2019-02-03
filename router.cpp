#include <net.hpp>

#include <vector>
#include <utility>
#include <chrono>
#include <map>
#include <iostream>
#include <fstream>
#include <queue>
#include <sstream>
#include <thread>

#include <boost/program_options.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/tokenizer.hpp>
#include <boost/algorithm/string.hpp>

#include <boost/graph/dijkstra_shortest_paths.hpp>
#include <boost/graph/adjacency_list.hpp>
#include <boost/graph/graph_traits.hpp>

namespace po = boost::program_options;
using TransportPacket = net::TransportPacket;

using packet_queue = std::queue<TransportPacket>;
static packet_queue outgoing_queue;
using topology = int;

using namespace boost;

// Graph stuff
typedef boost::adjacency_list < listS, vecS, undirectedS, no_property, boost::property < edge_weight_t, int > > graph_t;
typedef boost::graph_traits < graph_t >::vertex_descriptor vtx_desc;
typedef boost::graph_traits < graph_t >::edge_descriptor edge_desc;
typedef std::pair<int, int> edge_t;


// base topology of all known nodes (also contains link weights) -- adjacency list

// current node-specific topology (nodes of base topology may or may not be "active")

// dijkstra will generate (A,B,C)->(A,B,C) routes for the current node

// link states -> shortest paths -> forwarding table

struct forwarding_hop
{
    sockaddr_in hop_addr;
    uint32_t cost;

    forwarding_hop(const sockaddr_in & addr, uint32_t cost_) :
        hop_addr(addr), cost(cost_)
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
using topology_nodes = std::map<sockaddr_in, int, decltype(sockaddr_in_comp)>;
using topology_links = std::multimap<sockaddr_in, sockaddr_in, decltype(sockaddr_in_comp)>;

topology_nodes top_nodes(sockaddr_in_comp);
topology_links top_links(sockaddr_in_comp);

topology generate_topology(std::iostream & stream)
{
    topology top;

    // get vertices
    std::string line;
    uint32_t curr_node_id{0};

    while(std::getline(stream,line))
    {
        std::stringstream ss(line);
        try
        {
            std::string block;

            bool first_node_found{false};
            sockaddr_in first_node_addr;
            while (ss >> block)
            {
                std::vector<std::string> ip_port;
                boost::split(ip_port,block,boost::is_any_of(","));
                if (ip_port.size() != 2)
                    throw std::runtime_error("Could not parse an ip/port from block: " + block);

                sockaddr_in block_addr = net::get_sockaddr_in_from_hostport(ip_port.at(0),boost::lexical_cast<uint16_t>(ip_port.at(1)));
                if (!first_node_found)
                    first_node_addr = block_addr;
                
                if (!top_nodes.count(block_addr))
                    top_nodes.insert(std::make_pair(block_addr,curr_node_id++));

                if (first_node_found)
                {
                    if (first_node_addr == block_addr)
                        throw std::runtime_error("Topology file has self-directed edge");

                    top_links.insert(std::make_pair(first_node_addr,block_addr));
                }

                first_node_found = true;
            }

            if (!first_node_found)
                throw std::runtime_error("No head node found");
        }
        catch (std::exception & e)
        {
            throw std::runtime_error("generate_topology error. Could not parse line: " + line + "; " + e.what() + "\n");
        }
    }

    return top;
}

static void print_topology(const topology & top, std::ostream & stream)
{

}

static void routing_loop(const forwarding_table & ft, const net::sock_fd & recv_sock_fd, const sockaddr & router_addr,
    const uint32_t queue_max_size)
{
    std::array<uint8_t, net::RECV_BUFFER_SIZE> recv_buf;

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

            // else route it
            // first make sure the packet has a valid next-hop for its destination
            const sockaddr packet_dest_addr = recv_packet.get_transport_dest();

            if (ft.count(*(sockaddr_in*)&packet_dest_addr))
                outgoing_queue.push(std::move(recv_packet));
            else
                std::cout << "routing_loop event: packet dropped due to no valid next-hop\n";
        }
        // else if there is a packet being delayed and the delay is over
        else if (!outgoing_queue.empty())
        {
            // get forwarding hop
            const auto & front_packet = outgoing_queue.front();
            const sockaddr front_dest_addr = front_packet.get_transport_dest();
            const auto & forward_hop = ft.at(*(sockaddr_in*)&front_dest_addr);

#ifdef DEBUG_MSG
            const auto send_time = std::chrono::system_clock::now() - emulator_start_time;
            std::cout << "Packet. Type : " 
                << static_cast<std::underlying_type<net::BASE_PACKET_TYPE>::type>(front_packet.get_base_type())
                << "; Orig: " << net::sockaddr_to_str(front_packet.get_transport_src()) 
                << "; Dest: " << net::sockaddr_to_str(front_packet.get_transport_dest())
                << "; Hop: " << net::sockaddr_to_str(*(sockaddr*)&forward_hop.hop_addr)
                << "; Time (ms): " << std::chrono::duration_cast<std::chrono::milliseconds>(send_time).count()
                << "; SN: " << front_packet.get_seq_no()
                << '\n';
#endif
            front_packet.forward_packet(recv_sock_fd,*(sockaddr*)&forward_hop.hop_addr);
            outgoing_queue.pop();
        }
    }
}

int main(int argc, char * argv[])
{
    uint16_t emulator_port;
    std::string topology_filename;

    {
        po::options_description desc;
        try
        {
            desc.add_options()
                (",p", po::value<decltype(emulator_port)>(&emulator_port)->required(), "emulator port")
                (",f", po::value<decltype(topology_filename)>(&topology_filename)->required(), 
                    "topology filename");

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

    if (emulator_port < 1024)
    {
        std::cerr << "Emulator port must be >= 1024\n";
        return -1;
    }

    try
    {
        std::fstream top_file(topology_filename);
        if (!top_file.is_open())
        {
            std::cerr << "Could not open forwarding table file: " << topology_filename << '\n';
            return -1;
        }

        const auto recv_fd_addr = net::bind_recv_local(emulator_port);
        auto top = generate_topology(top_file);
        std::cout << "\nGenerated forwarding table for this node:\n"; print_topology(top,std::cout);

        //routing_loop(top,recv_fd_addr.first,recv_fd_addr.second);
    }
    catch (std::runtime_error & e)
    {
        std::cerr << "\nError generating forwarding table: " << e.what() << '\n' << std::flush;
        return -1;
    }

    return 0;
}
