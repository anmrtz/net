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
#include <mutex>

#include <boost/program_options.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/algorithm/string.hpp>

#include <boost/graph/dijkstra_shortest_paths.hpp>
#include <boost/graph/adjacency_list.hpp>
#include <boost/graph/graph_traits.hpp>
#include <boost/graph/graphviz.hpp>

namespace po = boost::program_options;
using TransportPacket = net::TransportPacket;

using packet_queue = std::queue<TransportPacket>;
static packet_queue outgoing_queue;

using namespace boost;

// Delay between sending node-active notifications to adjacent routers
static constexpr std::chrono::milliseconds NODE_HEARTBEAT_INTERVAL{200};
static_assert(NODE_HEARTBEAT_INTERVAL.count() >= 0, "NODE_HEARTBEAT_INTERVAL must be >= 0\n");

// Delay before pruning inactive nodes from the local topology state
static constexpr std::chrono::milliseconds NODE_EXPIRATION_INTERVAL{500};
static_assert(NODE_EXPIRATION_INTERVAL.count() >= 0, "NODE_EXPIRATION_INTERVAL must be >= 0\n");

// Graph stuff
struct vtx_prop
{
    sockaddr_in node_addr; // store the node address of each vertex
};
typedef boost::adjacency_list < setS, vecS, undirectedS, vtx_prop, boost::property < edge_weight_t, int > > topology_t;
typedef boost::graph_traits<topology_t>::edge_parallel_category disallow_parallel_edge_tag;
typedef boost::graph_traits < topology_t >::vertex_descriptor vtx_desc;
typedef boost::graph_traits < topology_t >::edge_descriptor edge_desc;

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
//using forwarding_table = std::map<sockaddr_in, forwarding_hop, decltype(sockaddr_in_comp)>; // destination, gateway emulator; process from forwarding_table
using forwarding_table = std::map<sockaddr_in, sockaddr_in, decltype(sockaddr_in_comp)>;
using topology_links = std::multimap<sockaddr_in, sockaddr_in, decltype(sockaddr_in_comp)>;

// topology and this-node reference states
topology_links top_links(sockaddr_in_comp);
sockaddr_in this_node_addr;
using adjacent_nodes_t = std::set<sockaddr_in, decltype(sockaddr_in_comp)>;
adjacent_nodes_t adjacent_nodes(sockaddr_in_comp);
topology_t top; // const topology graph

// running topology states
struct node_state
{
    uint32_t last_recv_seq_no{0};
    std::chrono::system_clock::time_point last_heartbeat_time;
    bool is_active{true};
    int node_id{-1};
};
using node_states_t = std::map<sockaddr_in, node_state, decltype(sockaddr_in_comp)>; 
node_states_t node_states(sockaddr_in_comp);
std::mutex socket_mtx;

// generate a set of all nodes adjacent to the specified node
static adjacent_nodes_t get_adj_nodes(const sockaddr_in & node)
{
    adjacent_nodes_t an(sockaddr_in_comp);

    for (const auto & link : top_links)
    {
        if (link.first == node)
        {
            an.insert(link.second);
        }
        else if (link.second == node)
        {
            an.insert(link.first);
        }
    }

    return an;
}

static topology_t generate_topology()
{
    topology_t top;

    for (auto & node : node_states)
    {
        auto vtx = boost::add_vertex(top);
        top[vtx].node_addr = node.first;
        node.second.node_id = vtx;
    }
    for (const auto & link : top_links)
    {
        auto l_node = node_states.at(link.first);
        auto r_node = node_states.at(link.second);

        if (l_node.is_active && r_node.is_active)
            boost::add_edge(l_node.node_id,r_node.node_id,1,top);
    }

    return top;
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

static forwarding_table generate_forwarding_table(const sockaddr_in & source_node, const topology_t & top)
{
    forwarding_table ft(sockaddr_in_comp);

    // calculate sample shortest path data
    std::vector<vtx_desc> parents(boost::num_vertices(top));
    std::vector<int> distances(boost::num_vertices(top));
    boost::dijkstra_shortest_paths(top,node_states.at(source_node).node_id, boost::predecessor_map(&parents[0]).distance_map(&distances[0]));

    // Output results
    typedef boost::graph_traits<topology_t>::vertex_iterator VItr;
    VItr vitr, vend;
    std::cout << "Dijkstra output from node " << node_states.begin()->second.node_id << " :\n";
    for (boost::tie(vitr, vend) = boost::vertices(top); vitr != vend; ++vitr) 
    {
        std::string node_name = net::sockaddr_to_str(top[*vitr].node_addr);

        std::cout << "distance(" << node_name << ") = " << distances[*vitr] << ", ";
        std::cout << "parent(" << node_name << ") = " << top[parents[*vitr]].node_addr << '\n';
    }
    std::cout << '\n';

    std::cout << "Generating forwarding paths from Dijkstra shortest paths...\n";
    for (const auto & node : node_states)
    {
        if (!node.second.is_active || node.first == this_node_addr)
            continue;

        auto src_idx = node_states.at(this_node_addr).node_id;
        // trace path
        std::deque<decltype(src_idx)> path_to;
        // get immediate parent
        decltype(src_idx) curr_idx = node.second.node_id;
        path_to.push_front(curr_idx);
        while (curr_idx != src_idx)
        {
            decltype(curr_idx) parent_of_curr = parents[curr_idx];
            path_to.push_front(parent_of_curr);
            curr_idx = parent_of_curr;
            std::cout << "Loop " << "cidx: " << curr_idx << "sidx: " << src_idx << "\n";
        }

        ft.insert(std::make_pair(node.first,top[path_to.at(1)].node_addr));
    }

    std::cout << "Printing forwarding table:\n";
    print_forwarding_table(ft,std::cout);

    return ft;
}

topology_t parse_topology(std::iostream & stream)
{
    // get vertices
    std::string line;

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

                if (!node_states.count(block_addr))
                {
                    node_state new_node;
                    new_node.last_heartbeat_time = std::chrono::system_clock::now();
                    node_states.insert(std::make_pair(block_addr,new_node));
                }

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
    if (!node_states.count(this_node_addr))
        throw std::runtime_error("Error: localhost addr - not found in topology file\n");

    auto top = generate_topology();

    // debug graph data
    typedef boost::graph_traits<topology_t>::vertex_iterator VItr;
    VItr vitr, vend;
    boost::tie( vitr, vend) = boost::vertices(top);
    std::vector<std::string> node_names;
    for (; vitr != vend; vitr++)
    {
        std::string node_name = net::sockaddr_to_str(top[*vitr].node_addr);
        node_names.push_back(node_name);
        std::cout << "Vertex: " << node_name << '\n';
    }

    auto EdgeWeightMap = get(boost::edge_weight_t(), top);
    typedef boost::graph_traits<topology_t>::edge_iterator EItr;
    EItr eitr, eend;
    boost::tie( eitr, eend) = boost::edges(top);
    for (; eitr != eend; eitr++)
    {
        std::cout << "Edge: " << EdgeWeightMap[*eitr] << '\n';
    }

    std::ofstream dotfile("top.dot");    
    write_graphviz (dotfile, top, make_label_writer(&node_names[0])); // output topology to dot file

    generate_forwarding_table(this_node_addr,top);

    return top;
}

static void print_topology(const topology_t & top, std::ostream & stream)
{
    std::vector<std::string> node_names;
    for (const auto & node : node_states)
        node_names.push_back(net::sockaddr_to_str(node.first));

    write_graphviz (stream, top, make_label_writer(&node_names[0]));
}

// update the known topology based on the received node state message (or expiration of node state)
// update the forwarding table based on the changed topology
// forward node state packets to neighbors
static void process_node_state(const sockaddr & src_addr, uint32_t seq_no)
{

}

// periodically check to see if nodes have expired due to lack of recent heartbeat packets from those nodes
static void node_timeout_loop()
{
    // do not check self!!!

}

// periodically send node heartbeats to adjacent nodes
static void send_node_update_loop(const net::sock_fd & recv_sock_fd)
{
    static uint32_t curr_seq_no{0};

    net::TransportPacket heartbeat(net::BASE_PACKET_TYPE::LINK, net::TransportPacket::TRANSPORT_PRIORITY::HIGH, *(sockaddr*)&this_node_addr, 
        {0}, curr_seq_no); // These are intended as "broadcast" messages and therefore do not have a specific dest address

    while (true)
    {
        std::this_thread::sleep_for(NODE_HEARTBEAT_INTERVAL);

        // mutex for socket
        {
            std::lock_guard<std::mutex> lock(socket_mtx);

        }

    }
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

        // mutex for socket
        int recv_len{0};
        {
            std::lock_guard<std::mutex> lock(socket_mtx);
            recv_len = recvfrom(recv_sock_fd.get(), recv_buf.data(), recv_buf.size(), 0, &src_addr, &src_addr_len);
        }
        // if packet has been received...
        if (recv_len > 0)
        {
            TransportPacket recv_packet(recv_buf.data(), recv_len);

            // Check if this is a node-state packet
            if (recv_packet.get_base_type() == net::BASE_PACKET_TYPE::LINK)
            {
                process_node_state(recv_packet.get_transport_src(), recv_packet.get_seq_no());
                continue;
            }

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
                << "; Hop: " << net::sockaddr_to_str(*(sockaddr*)&forward_hop)
                << "; Time (ms): " << std::chrono::duration_cast<std::chrono::milliseconds>(send_time).count()
                << "; SN: " << front_packet.get_seq_no()
                << '\n';
#endif
            {
                std::lock_guard<std::mutex> lock(socket_mtx);
                front_packet.forward_packet(recv_sock_fd,*(sockaddr*)&forward_hop);
            }    
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
                    "topology_t filename");

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

        //const auto recv_fd_addr = net::bind_recv_local(emulator_port);
        this_node_addr = net::get_sockaddr_in_from_hostport("localhost",emulator_port);
        std::cout << "Localhost found at: " << this_node_addr << "\n";
        auto top = parse_topology(top_file);
        std::cout << "\nTopology for this node:\n"; print_topology(top,std::cout);

        //routing_loop(top,recv_fd_addr.first,recv_fd_addr.second);
    }
    catch (std::runtime_error & e)
    {
        std::cerr << "\nError generating forwarding table: " << e.what() << '\n' << std::flush;
        return -1;
    }

    return 0;
}
