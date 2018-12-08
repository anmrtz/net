#include <net.hpp>

#include <tuple>
#include <iostream>
#include <fstream>
#include <algorithm>

#include <boost/lexical_cast.hpp>

namespace net
{

void set_buffer_size(int fd, int size)
{
    if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size)) == -1)
        std::cerr << "setsocktop error: failed to set buffer size\n";
}

net::tracker_table generate_tracker_table(const std::string & table_filename)
{
    net::tracker_table tt;

    std::ifstream tracker;
    tracker.open(table_filename.c_str());
    if (!tracker.is_open())
        throw std::runtime_error("Error: tracker.txt not found\n");

    std::string line;
    while (std::getline(tracker,line))
    {
        std::stringstream ss(line);

        std::string filename;
        uint16_t id;
        net::hostname host;
        uint16_t port;
        std::string num_str;

        try
        {
            ss >> filename;
            ss >> num_str; id = boost::lexical_cast<uint16_t>(num_str);
            ss >> host;
            ss >> num_str; port = boost::lexical_cast<uint16_t>(num_str);

            tt.push_back(std::make_tuple(filename,id,host,port));
        }
        catch(std::exception & e)
        {
            throw std::runtime_error("Error reading line: " + line + " - " +  e.what() + '\n');
        }
    }

    return tt;
}

void print_tracker_table(const net::tracker_table & tt)
{
    for (const auto & entry : tt)
    {
        std::string filename;
        uint16_t id;
        net::hostname host;
        uint16_t port;

        std::tie(filename,id,host,port) = entry;

        std::cerr << "Table entry: " << filename << "," << id << "," << host << "," << port << "\n";
    }
}

std::shared_ptr<addrinfo> hostname_to_ip4(net::hostname host, uint16_t port)
{
    std::string portname = boost::lexical_cast<std::string>(port);

    addrinfo addr_hints;
    memset(&addr_hints, 0 ,sizeof(addr_hints));
    addr_hints.ai_family = AF_INET;
    addr_hints.ai_socktype = SOCK_DGRAM;
    addr_hints.ai_flags = AI_ADDRCONFIG;

    addrinfo * ip_addr{nullptr};

    getaddrinfo(host.c_str(),portname.c_str(),&addr_hints,&ip_addr);

    return std::shared_ptr<addrinfo>(ip_addr, [](addrinfo* a)
        {
            if (a)
            {
                freeaddrinfo(a);
            }
        });
}

std::string sockaddr_to_str(const sockaddr & addr)
{
    sockaddr_in * src_addr_in = (sockaddr_in*)&addr;
    return std::string(inet_ntoa(src_addr_in->sin_addr));
}

// ip and port specified in network order
sockaddr ip4_port_to_sockaddr(uint32_t ip, uint16_t port)
{
    sockaddr_in in_addr;
    memset(&in_addr, 0, sizeof(in_addr));
    in_addr.sin_family = AF_INET;

    memcpy(&in_addr.sin_addr, &ip, sizeof(ip));
    memcpy(&in_addr.sin_port, &port, sizeof(port));

    sockaddr * addr = (sockaddr*)&in_addr;
    return *addr;
}

static BaseHeader generate_base_header(BASE_PACKET_TYPE p_type, uint32_t seq_no = 0, uint32_t size = 0)
{
    auto type = static_cast<std::underlying_type<BASE_PACKET_TYPE>::type>(p_type);
    static_assert(std::is_same<decltype(type), uint8_t>::value);

    BaseHeader bh;

    // form header
    bh.packet_type = type;
    bh.seq_no = htonl(seq_no);
    bh.payload_size = htonl(size);

    return bh;
}

BaseHeader parse_base_header(const uint8_t * bh_data)
{
    BaseHeader bh{0};

    bh.packet_type = *bh_data;
    // check for valid packet type!!!

    static_assert(BASE_HEADER_PACKED_SIZE == 9);
    memcpy(&bh.seq_no, bh_data + 1, 4);
    memcpy(&bh.payload_size, bh_data + 5, 4);

    return bh;
}

static TransportPacket::TransportHeader generate_transport_header(TransportPacket::TRANSPORT_PRIORITY tp, const sockaddr & src, const sockaddr & dest, uint32_t base_packet_size)
{
    auto priority = static_cast<std::underlying_type<TransportPacket::TRANSPORT_PRIORITY>::type>(tp);
    static_assert(std::is_same<decltype(priority), uint8_t>::value);

    const sockaddr_in * src_in = (sockaddr_in*)&src;
    const sockaddr_in * dest_in = (sockaddr_in*)&dest;
    assert(src_in->sin_family == AF_INET);
    assert(dest_in->sin_family == AF_INET);
    
    TransportPacket::TransportHeader th;

    th.priority = priority;    
    memcpy(&th.src_ip, &src_in->sin_addr, 4);
    memcpy(&th.src_port, &src_in->sin_port, 2);
    memcpy(&th.dest_ip, &dest_in->sin_addr, 4);
    memcpy(&th.dest_port, &dest_in->sin_port, 2);
    th.base_packet_size = htonl(base_packet_size);

    return th;
}

TransportPacket::TransportHeader TransportPacket::parse_transport_header(const uint8_t * th_data)
{
    TransportPacket::TransportHeader th{0};

    th.priority = *th_data;
    // check for valid priority!!!

    static_assert(TRANSPORT_HEADER_PACKED_SIZE == 17);
    memcpy(&th.src_ip, th_data + 1, 4);
    memcpy(&th.src_port, th_data + 5, 2);
    memcpy(&th.dest_ip, th_data + 7, 4);
    memcpy(&th.dest_port, th_data + 11, 2);
    memcpy(&th.base_packet_size, th_data + 13, 4);

    return th;
}

TransportPacket::TransportPacket(uint8_t * packet_start, std::size_t packet_size)
{
    if (packet_size < TRANSPORT_HEADER_PACKED_SIZE + BASE_HEADER_PACKED_SIZE)
        throw std::runtime_error("TransportPacket::TransportPacket() error: packet_size too small for transport and base header\n");

    bh_ = parse_base_header(packet_start + TRANSPORT_HEADER_PACKED_SIZE);
    
    const uint32_t parsed_payload_size = ntohl(bh_.payload_size);
    const uint32_t observed_payload_size = packet_size - (TRANSPORT_HEADER_PACKED_SIZE + BASE_HEADER_PACKED_SIZE);
    if (parsed_payload_size != observed_payload_size)
        throw std::runtime_error("TransportPacket::TransportPacket() error: parsed payload size (" + std::to_string(parsed_payload_size) + 
            ") does not match with packet size parameter (" + std::to_string(observed_payload_size) + ")\n");

    th_ = parse_transport_header(packet_start);

    const uint32_t parsed_base_packet_size = ntohl(th_.base_packet_size);
    if (parsed_base_packet_size != packet_size - (TRANSPORT_HEADER_PACKED_SIZE))    
        throw std::runtime_error("TransportPacket::TransportPacket() error: parsed base packet size does not match with packet size parameter\n");

    this->payload_ = std::vector<uint8_t>(packet_start + TRANSPORT_HEADER_PACKED_SIZE + BASE_HEADER_PACKED_SIZE,
        packet_start + TRANSPORT_HEADER_PACKED_SIZE + BASE_HEADER_PACKED_SIZE + parsed_payload_size);
}

// used to construct outgoing packets
// will throw if no payload provided for data packets
TransportPacket::TransportPacket(BASE_PACKET_TYPE pt, TRANSPORT_PRIORITY tp, const sockaddr & src, const sockaddr & dest, uint32_t seq_no, const std::vector<uint8_t> & payload)
{
    bh_ = generate_base_header(pt, seq_no, payload.size());
    th_ = generate_transport_header(tp,src,dest,BASE_HEADER_PACKED_SIZE + payload.size());
    this->payload_ = payload;
}

std::size_t TransportPacket::send_packet(const sock_fd & fd) const
{
    return forward_packet(fd, get_transport_dest());
}

std::size_t TransportPacket::forward_packet(const sock_fd & fd, const sockaddr & dest_ip_addr) const
{
    packed_th th_packed(pack_transport_header(th_));
    packed_bh bh_packed(pack_base_header(bh_));

    // specify data blocks that form entire packet
    iovec iov[3];
    iov[0].iov_base = th_packed.data();
    iov[0].iov_len = th_packed.size();
    iov[1].iov_base = bh_packed.data();
    iov[1].iov_len = bh_packed.size();
    iov[2].iov_base = (void*)payload_.data();
    iov[2].iov_len = payload_.size();

    // set message address
    msghdr message{0};

    message.msg_name = (void*)&dest_ip_addr;
    message.msg_namelen = sizeof(dest_ip_addr);
    message.msg_iov = iov;
    message.msg_iovlen = 3;
    message.msg_control = 0;
    message.msg_controllen = 0;

    return sendmsg(fd.get(), &message, 0);
}

TransportPacket::TRANSPORT_PRIORITY TransportPacket::get_priority() const
{
    return static_cast<TransportPacket::TRANSPORT_PRIORITY>(this->th_.priority);
}

sockaddr TransportPacket::get_transport_src() const
{
    return ip4_port_to_sockaddr(th_.src_ip, th_.src_port);
}

sockaddr TransportPacket::get_transport_dest() const
{
    return ip4_port_to_sockaddr(th_.dest_ip, th_.dest_port);
}

BASE_PACKET_TYPE TransportPacket::get_base_type() const
{
    return static_cast<BASE_PACKET_TYPE>(this->bh_.packet_type);
}

const std::vector<uint8_t> & TransportPacket::get_payload() const
{
    return this->payload_;
}

uint32_t TransportPacket::get_seq_no() const
{
    return ntohl(this->bh_.seq_no);
}

uint32_t TransportPacket::get_payload_size() const
{
    return ntohl(this->bh_.payload_size);
}

TransportPacket::packed_th TransportPacket::pack_transport_header(const TransportHeader & th)
{
    packed_th p_th;

    std::memcpy(p_th.data(), &(th.priority), sizeof(th.priority));
    std::memcpy(p_th.data()+1, &(th.src_ip), sizeof(th.src_ip));
    std::memcpy(p_th.data()+5, &(th.src_port), sizeof(th.src_port));
    std::memcpy(p_th.data()+7, &(th.dest_ip), sizeof(th.dest_ip));
    std::memcpy(p_th.data()+11, &(th.dest_port), sizeof(th.dest_port));
    std::memcpy(p_th.data()+13, &(th.base_packet_size), sizeof(th.base_packet_size));

    return p_th;
}

packed_bh pack_base_header(const BaseHeader & bh)
{
    packed_bh p_bh;

    std::memcpy(p_bh.data(), &(bh.packet_type), sizeof(bh.packet_type));
    std::memcpy(p_bh.data() + 1, &(bh.seq_no), sizeof(bh.seq_no));
    std::memcpy(p_bh.data() + 5, &(bh.payload_size), sizeof(bh.payload_size));

    return p_bh;
}

bool TransportPacket::operator==(const TransportPacket& right) const
{
    return 
        bh_.packet_type == right.bh_.packet_type &&
        bh_.seq_no == right.bh_.seq_no &&
        bh_.payload_size == right.bh_.payload_size &&
        std::equal(payload_.begin(),payload_.end(), right.payload_.begin()) &&

        th_.priority == right.th_.priority &&
        th_.base_packet_size == right.th_.base_packet_size &&
        th_.dest_ip == right.th_.dest_ip &&
        th_.dest_port == right.th_.dest_port &&
        th_.src_ip == right.th_.src_ip &&
        th_.src_port == right.th_.src_port
    ;
}

bool TransportPacket::operator<(const TransportPacket& right) const
{
    return ntohl(bh_.seq_no) < ntohl(right.bh_.seq_no);
}

uint32_t get_next_expected_seq_no(const std::set<TransportPacket> & window, const uint32_t window_start_seq_no)
{
    if (window.empty() || window.begin()->get_seq_no() != window_start_seq_no)
    {
        return window_start_seq_no;
    }
    else
    {
        // find end of contiguous set
        uint32_t next_expected_seq_no;
        for (auto i = window.begin(); i != window.end(); i++)
        {
            const auto & curr_packet = *i;
            next_expected_seq_no = curr_packet.get_seq_no() + curr_packet.get_payload_size();
            
            const auto next_packet_iter = std::next(i);
            if (next_packet_iter != window.end())
            {
                const auto & next_packet = *next_packet_iter;
                if (next_packet.get_seq_no() != next_expected_seq_no)
                    break;
            }
        }
        return next_expected_seq_no;
    }
}

}
