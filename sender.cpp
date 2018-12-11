#include <net.hpp>

#include <boost/program_options.hpp>

#include <string>
#include <iostream>
#include <fstream>
#include <thread>
#include <chrono>
#include <queue>

namespace po = boost::program_options;
using TransportPacket = net::TransportPacket;

static uint32_t send_data_packets(const net::sock_fd & fd, const std::set<TransportPacket> & window, 
    const uint32_t curr_window_start,const std::chrono::nanoseconds & per_packet_delay)
{
    if (window.empty())
        return curr_window_start;

    if (window.begin()->get_seq_no() != curr_window_start)
        throw std::runtime_error("send_data_packets error: "
            "beginning of send window seq number does not match current highest ack number\n");

    const auto send_start_time = std::chrono::system_clock::now();
    auto send_wake_time = send_start_time; // time at which send is enabled (to maintain set packet rate)

    // verify that sequence numbers are contiguous
    for (auto curr_packet_iter = window.begin(); curr_packet_iter != window.end(); curr_packet_iter++)
    {
        const auto & curr_packet = *curr_packet_iter;
        if (curr_packet_iter != window.begin())
        {
            const auto & prev_packet = *std::prev(curr_packet_iter);
            if (prev_packet.get_seq_no() + prev_packet.get_payload_size() != curr_packet.get_seq_no())
                throw std::runtime_error("send_data_packets error: sequence numbers not contiguous\n");
        }
    }

    // send the packets with delay
    for (const auto & packet : window)
    {
        std::this_thread::sleep_until(send_wake_time);
        send_wake_time += per_packet_delay;

        const auto & payload_chunk = packet.get_payload();

        std::cout << "Sending data packet. Send time (ms): " <<
            std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now() - 
                send_start_time).count() <<
            "; Dest addr: " << net::sockaddr_to_str(packet.get_transport_dest()) <<
            "; Seq no: " << packet.get_seq_no() <<
            "; Payload size: " << payload_chunk.size() <<
            "; First 4 bytes of payload: \"";

        std::cout << std::string(payload_chunk.begin(), payload_chunk.begin() + 
            std::min(payload_chunk.size(),std::size_t(4)));
        std::cout << "\"\n";

        packet.send_packet(fd);
    }

    return (window.rbegin()->get_seq_no() + window.rbegin()->get_payload_size());
}

static std::set<TransportPacket> queue_data_packets(std::vector<uint8_t> & data_vector, const uint32_t window_size, 
    const uint32_t payload_chunk_size, const uint32_t curr_ack_no, const sockaddr & src_addr, const sockaddr & dest_addr)
{
    std::set<TransportPacket> packets;

    uint32_t curr_window_segment{0};
    uint32_t curr_seq_no{curr_ack_no};

    while (!data_vector.empty() && curr_window_segment < window_size)
    {
        decltype(data_vector.begin()) chunk_end_pos;
        if (data_vector.size() < payload_chunk_size)
            chunk_end_pos = data_vector.end();
        else
            chunk_end_pos = data_vector.begin() + payload_chunk_size;
        if (chunk_end_pos > data_vector.end())
            throw std::runtime_error("payload chunking error: chunk_pos went past end()\n");

        auto curr_data = packets.emplace(net::BASE_PACKET_TYPE::DATA, TransportPacket::TRANSPORT_PRIORITY::HIGH,
            src_addr, dest_addr, curr_seq_no, std::vector<uint8_t>(data_vector.begin(), chunk_end_pos));

        curr_seq_no += curr_data.first->get_payload_size();
        ++curr_window_segment;
    
        data_vector.erase(data_vector.begin(), chunk_end_pos);
    }

    std::cerr << "Queue assembled. Size: " << packets.size() << "\n";

    return packets;
}

static void send_end_packet(const net::sock_fd & fd, const sockaddr & src_addr, const sockaddr & dest_addr)
{
    TransportPacket end_packet(net::BASE_PACKET_TYPE::END, TransportPacket::TRANSPORT_PRIORITY::HIGH,src_addr,
        dest_addr);

    std::cout << "Sending end packet\n";

    end_packet.send_packet(fd);
}

int main(int argc, char * argv[])
{
    uint8_t packet_priority;
    uint16_t sender_port, requester_port, packet_rate, payload_chunk_size, emulator_port;
    uint32_t resend_timeout;
    std::string emulator_hostname;
    {
        po::options_description desc;
        try
        {
            desc.add_options()
                (",p", po::value<uint16_t>(&sender_port)->required(), "sender port")
                (",g", po::value<uint16_t>(&requester_port)->required(), "requester port")
                (",r", po::value<uint16_t>(&packet_rate)->required(), "packet rate")
                (",l", po::value<uint16_t>(&payload_chunk_size)->required(), "payload length")
                (",f", po::value<std::string>(&emulator_hostname)->required(), "emulator hostname")
                (",h", po::value<uint16_t>(&emulator_port)->required(), "emulator port")
                (",i", po::value<uint8_t>(&packet_priority)->required(), "packet priority")
                (",t", po::value<uint32_t>(&resend_timeout)->required(), "resend timeout");

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

    // can probably do this through program options api...
    if (sender_port < 1024 || requester_port < 1024 || emulator_port < 1024)
    {
        std::cerr << "Invalid port number. Must be > 1023\n";
        return -1;
    }

    if (packet_rate < 1)
    {
        std::cerr << "Invalid packet rate. Must be > 0\n";
        return -1;
    }
    constexpr std::chrono::nanoseconds DURATION_ONE_SECOND{1'000'000'000};
    // verify that the clock has enough resolution for the range of possible packet rates
    static_assert(std::numeric_limits<decltype(packet_rate)>::max() <= DURATION_ONE_SECOND.count(),
        "Maximim packet rate exceeds clock resolution");

    if (payload_chunk_size < 1)
    {
        std::cerr << "Invalid payload length. Must be > 0\n";
        return -1;
    }
    else if (payload_chunk_size > net::RECV_BUFFER_SIZE - 9)
    {
        std::cerr << "Invalid payload length. Payload length plus required 9 byte header exceeds specified recv buffer size: " <<
            net::RECV_BUFFER_SIZE << '\n';
        return -1;
    }

    auto tt = net::generate_tracker_table();

    // verify that the input parameters match the tracker table
    for (const auto & entry : tt)
    {
        std::string filename;
        uint16_t id;
        net::hostname host;
        uint16_t port;

        std::tie(filename,id,host,port) = entry;
    }

    // get file data
    std::ifstream data_file("chunk.txt", std::ios::binary);
    // verify file was opened
    if (!data_file.is_open())
    {
        std::cerr << "Error: could not open sender data file\n";
        return -1;
    }
    std::vector<uint8_t> data_vector((std::istreambuf_iterator<char>(data_file)), 
        std::istreambuf_iterator<char>());

    auto recv_fd_addr = net::bind_recv_local(sender_port);
    const auto & recv_sock_fd = recv_fd_addr.first;
    const auto & sender_addr = recv_fd_addr.second;

    // initialize blocking UDP send socket
    const net::sock_fd send_sock_fd(socket(AF_INET, SOCK_DGRAM, 0));
    net::set_buffer_size(send_sock_fd.get());
    if (send_sock_fd.get() < 0)
    {
        std::cerr << "Could not initialize send socket\n";
        return -1;
    }

    std::chrono::time_point<std::chrono::system_clock> most_recent_packet_time{std::chrono::system_clock::now()};
    std::remove_const<decltype(net::MAX_TIMEOUT_COUNT)>::type timeout_count{0};
    const auto packet_time_interval = DURATION_ONE_SECOND / packet_rate;

    bool is_request_pending{false};
    bool end_sent{false};
    sockaddr request_packet_src_addr{0};
    std::array<uint8_t, net::RECV_BUFFER_SIZE> recv_buf;
    std::set<TransportPacket> send_window;
    uint32_t window_size{0};
    uint32_t curr_window_start{0};
    uint32_t curr_highest_ack_expected{0};
    uint32_t curr_highest_ack_received{0};

    while (true)
    {
        std::this_thread::sleep_for(net::RECV_LOOP_DELAY);

        sockaddr src_addr;
        memset(&src_addr, 0, sizeof(src_addr));
        socklen_t src_addr_len{sizeof(src_addr)};

        int recv_len = recvfrom(recv_sock_fd.get(), recv_buf.data(), recv_buf.size(), 0, &src_addr, &src_addr_len);
        if (recv_len > 0)
        {
            most_recent_packet_time = std::chrono::system_clock::now();

            const TransportPacket recv_packet(recv_buf.data(), recv_len);
            const auto base_type = recv_packet.get_base_type();
            const auto type = static_cast<std::underlying_type<net::BASE_PACKET_TYPE>::type>(base_type);

            std::cerr << "Packet received! Type: " << type << "; Total packet size: " << recv_len <<
                "; Src addr: " << net::sockaddr_to_str(src_addr) <<
                "; Seq no: " << recv_packet.get_seq_no() << "; Payload size: " << recv_packet.get_payload_size() << '\n';


            if (base_type == net::BASE_PACKET_TYPE::REQUEST)
            {
                if (is_request_pending)
                    std::cerr << "Sender error: received request packet while still sending data\n";
                is_request_pending = true;
                request_packet_src_addr = recv_packet.get_transport_src();
                window_size = recv_packet.get_seq_no();

                std::cerr << "Request packet received from addr: " << net::sockaddr_to_str(request_packet_src_addr) <<
                    "; Requester advertised window size: " << window_size << '\n';

                send_window = queue_data_packets(data_vector, window_size,payload_chunk_size,curr_window_start,
                    sender_addr,request_packet_src_addr);
                curr_highest_ack_expected = send_data_packets(send_sock_fd,send_window,curr_window_start,packet_time_interval);
            }
            else if (base_type == net::BASE_PACKET_TYPE::ACK)
            {
                if (!is_request_pending)
                    std::cerr << "Sender error: received ack packet without request\n";

                // loop queue
                if (recv_packet.get_seq_no() > curr_highest_ack_received)
                {
                    if (recv_packet.get_seq_no() > curr_highest_ack_expected)
                    {
                        std::cerr << "sender error: received ack packet higher than expected range\n";
                        return -1;
                    }
                    else
                        curr_highest_ack_received = recv_packet.get_seq_no();
                }

                if (curr_highest_ack_received == curr_highest_ack_expected)
                {
                    if (!data_vector.empty())
                    {
                        curr_window_start = curr_highest_ack_received;
                        send_window = queue_data_packets(data_vector, window_size,payload_chunk_size,curr_window_start,
                            sender_addr,request_packet_src_addr);
                        curr_highest_ack_expected = send_data_packets(send_sock_fd,send_window,curr_window_start,packet_time_interval);
                    }
                    else if (end_sent)
                    {
                        break;
                    }
                    else
                    {
                        // fix src_addr - amend this to send to gateway rather than directly back
                        send_end_packet(send_sock_fd, sender_addr,request_packet_src_addr);
                        end_sent = true;
                    }
                }
            }
        }
        // account for timeout
        else if (is_request_pending && most_recent_packet_time + net::SENDER_RECV_TIMEOUT < std::chrono::system_clock::now())
        {
            if (++timeout_count > net::MAX_TIMEOUT_COUNT)
            {
                std::cerr << "Sender timed out waiting for response\n";
                return -1;
            }

            if (end_sent)
                send_end_packet(send_sock_fd,sender_addr,request_packet_src_addr);
            else
                send_data_packets(send_sock_fd,send_window,curr_window_start,packet_time_interval);
        }
    }

    std::cerr << "Sender terminated normally\n";
    return 0;
}
