#pragma once

#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>

#include <string>
#include <vector>
#include <set>
#include <memory>
#include <chrono>

namespace net
{

using hostname = std::string;
using tracker_entry = std::tuple <std::string, uint16_t, hostname, uint16_t>; // filename, seq, hostname, port
using tracker_table = std::vector<tracker_entry>;

constexpr std::chrono::microseconds RECV_LOOP_DELAY{1};
static_assert(RECV_LOOP_DELAY.count() >= 0, "RECV_LOOP_DELAY must be >= 0\n");
constexpr std::chrono::milliseconds REQUESTER_RECV_TIMEOUT{1000};
static_assert(REQUESTER_RECV_TIMEOUT.count() >= 0, "REQUESTER_RECV_TIMEOUT must be >= 0\n");
static_assert(REQUESTER_RECV_TIMEOUT > RECV_LOOP_DELAY, "recv loop time slice too large to capture packet timeouts\n");
constexpr std::chrono::milliseconds SENDER_RECV_TIMEOUT{1000};
static_assert(SENDER_RECV_TIMEOUT.count() >= 0, "SENDER_RECV_TIMEOUT must be >= 0\n");
static_assert(SENDER_RECV_TIMEOUT > RECV_LOOP_DELAY, "recv loop time slice too large to capture packet timeouts\n");

constexpr uint8_t MAX_TIMEOUT_COUNT{3};
static_assert(MAX_TIMEOUT_COUNT > 0, "Max timeout must be > 0");

// automatically clean-up out of scope socket fd
class sock_fd
{
    public:
    sock_fd(int fd_)
    : fd(fd_)
    {}

    sock_fd(const sock_fd &) = delete;
    sock_fd& operator=(sock_fd &) = delete;

    int get() const
    {
        return fd;
    }
    
    ~sock_fd()
    {
        if (fd >= 0)
        {
            close(fd);
        }
    }

    private:
    int fd{-1};
};

enum class BASE_PACKET_TYPE : uint8_t
{
    REQUEST = 'R',
    DATA = 'D',
    END = 'E',
    ACK = 'A'
};

// base header fields stored in network order
struct BaseHeader
{
    uint8_t packet_type;
    uint32_t seq_no;
    uint32_t payload_size;
};
constexpr std::size_t BASE_HEADER_PACKED_SIZE{9};
using packed_bh = std::array<uint8_t, BASE_HEADER_PACKED_SIZE>;
packed_bh pack_base_header(const BaseHeader & bh);
BaseHeader parse_base_header(const uint8_t * bh_data);

class TransportPacket
{
    public:

    enum class TRANSPORT_PRIORITY : uint8_t
    {
        HIGH = 0x01,
        MEDIUM = 0x02,
        LOW = 0x03
    };

    // transport header fields stored in network order
    struct TransportHeader
    {
        uint8_t priority;
        uint32_t src_ip;
        uint16_t src_port;
        uint32_t dest_ip;
        uint16_t dest_port;
        uint32_t base_packet_size;
    };
    static constexpr std::size_t TRANSPORT_HEADER_PACKED_SIZE{17};
    using packed_th = std::array<uint8_t, TRANSPORT_HEADER_PACKED_SIZE>;
    static packed_th pack_transport_header(const TransportHeader & th);

    // construct transport packet from data chunk
    // used to parse out received packets
    // will throw if packet_size is not large enough to hold required headers
    // will throw if packet_size is also not large enough to hold payload size specified in transport header
    TransportPacket(uint8_t * packet_start, std::size_t packet_size);
    // used to construct outgoing packets
    // will throw if no payload provided for data packets
    TransportPacket(BASE_PACKET_TYPE pt, TRANSPORT_PRIORITY tp, const sockaddr & src, const sockaddr & dest, 
        uint32_t seq_no = 0, const std::vector<uint8_t> & payload = {});

    std::size_t forward_packet(const sock_fd & fd, const sockaddr & dest_ip_addr) const;
    std::size_t send_packet(const sock_fd & fd) const;

    sockaddr get_transport_src() const;
    sockaddr get_transport_dest() const;
    TRANSPORT_PRIORITY get_priority() const;
    BASE_PACKET_TYPE get_base_type() const;
    uint32_t get_seq_no() const;
    uint32_t get_payload_size() const;
    const std::vector<uint8_t> & get_payload() const;

    bool operator==(const TransportPacket& right) const;
    bool operator<(const TransportPacket& right) const;

    TransportPacket(const TransportPacket&) = delete;
    TransportPacket& operator=(const TransportPacket&) = delete;
    TransportPacket(TransportPacket&&) = default;

    private:

    TransportPacket() = default;

    TransportHeader th_{0};
    BaseHeader bh_{0};

    std::vector<uint8_t> payload_;

    static TransportHeader parse_transport_header(const uint8_t * th_data);
};

constexpr uint32_t RECV_BUFFER_SIZE{4096};
static_assert(RECV_BUFFER_SIZE > BASE_HEADER_PACKED_SIZE + TransportPacket::TRANSPORT_HEADER_PACKED_SIZE);

void set_buffer_size(int fd, int size = 4096 * 1024);

net::tracker_table generate_tracker_table(const std::string & table_filename = "tracker.txt");

void print_tracker_table(const net::tracker_table & tt);

std::shared_ptr<addrinfo> hostname_to_ip4(net::hostname host, uint16_t port);

std::string sockaddr_to_str(const sockaddr & addr);

uint32_t get_next_expected_seq_no(const std::set<TransportPacket> & window, const uint32_t window_start_seq_no);

}
