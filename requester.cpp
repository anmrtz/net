#include <net.hpp>

#include <boost/program_options.hpp>

#include <algorithm>
#include <string>
#include <iostream>
#include <thread>
#include <fstream>
#include <chrono>
#include <future>

namespace po = boost::program_options;
using job_queue_t = std::vector<net::tracker_entry>;
using TransportPacket = net::TransportPacket;

static job_queue_t generate_job_queue(const std::string & requested_file)
{
    auto tt = net::generate_tracker_table();

    job_queue_t job_queue;
    for (const auto & entry : tt)
    {
        if (std::get<0>(entry) == requested_file)
            job_queue.push_back(entry);
    }

    net::print_tracker_table(tt);

    if (job_queue.empty())
        throw std::runtime_error("Error: No tracker entries found for " + requested_file + '\n');

    // sort by ID
    std::sort(job_queue.begin(), job_queue.end(), [](const auto & t1, const auto & t2)
    {
        return std::get<1>(t1) < std::get<1>(t2);
    });

    // ensure tracker entries are contiguous
    uint16_t id_tracker{1};
    for (const auto & job : job_queue)
    {
        if (std::get<1>(job) != id_tracker++)
            throw std::runtime_error("Error: tracker ID values out of sequence (1,2,..,n)\n");
    }

    return job_queue;
}

static void append_window_packets(const std::set<TransportPacket> & recv_window, std::vector<uint8_t> & file_chunk)
{
    // first verify that window packets represent contiguous range
    for (auto i = recv_window.begin(); i != recv_window.end(); i++)
    {
        if (i != recv_window.begin())
        {
            const auto iter_prev = std::prev(i);
            if (i->get_seq_no() != iter_prev->get_seq_no() + iter_prev->get_payload_size())
                throw std::runtime_error("append_window_packets error: packet set not contiguous\n");
        }
    }

    // then append
    for (const auto & packet : recv_window)
    {
        const auto & payload = packet.get_payload();
        std::copy(payload.begin(), payload.end(), std::back_inserter(file_chunk));
    }
}

static void send_ack_packet(const net::sock_fd & fd, const sockaddr & src_addr, const sockaddr & dest_addr, 
    const uint32_t next_expected_seq_no)
{
    TransportPacket ack_packet(net::BASE_PACKET_TYPE::ACK, TransportPacket::TRANSPORT_PRIORITY::HIGH, 
        src_addr, dest_addr, next_expected_seq_no);

    std::cout << "Sending ACK" << '\n';

    ack_packet.send_packet(fd);
}

static std::vector<uint8_t> requester_recv_task(const net::sock_fd & recv_sock_fd, const sockaddr_in recv_addr, 
    const net::sock_fd & send_sock_fd, const std::size_t recv_window_size = 1)
{
    std::array<uint8_t, net::RECV_BUFFER_SIZE> recv_buf;
    sockaddr src_addr;
    socklen_t src_addr_len{sizeof(src_addr)};
    int recv_len;

    std::vector<uint8_t> file_chunk;

    // variables used for statistics output
    std::size_t data_packets_received{0};
    std::chrono::time_point<std::chrono::system_clock> first_data_packet_time;
    std::chrono::time_point<std::chrono::system_clock> most_recent_packet_time{std::chrono::system_clock::now()};
    std::chrono::time_point<std::chrono::system_clock> end_packet_time;

    // receiver window
    std::set<TransportPacket> recv_window;

    bool first_data_packet_received{false};
    uint32_t window_start_seq_no{0};
    uint32_t next_expected_seq_no{window_start_seq_no};
    while (true)
    {
        std::this_thread::sleep_for(net::RECV_LOOP_DELAY);

        recv_len = recvfrom(recv_sock_fd.get(), recv_buf.data(), recv_buf.size(), 0, &src_addr, &src_addr_len);
        if (recv_len > 0)
        {
            TransportPacket recv_packet(recv_buf.data(), recv_len);
            const auto base_type = recv_packet.get_base_type();

            most_recent_packet_time = std::chrono::system_clock::now();

            if (base_type == net::BASE_PACKET_TYPE::END)
            {
                end_packet_time = most_recent_packet_time;

                if (!recv_window.empty() && window_start_seq_no != recv_window.begin()->get_seq_no())
                    throw std::runtime_error("requester_recv_task window ended but start sequence number doesn't match\n");

                append_window_packets(recv_window, file_chunk);
                recv_window.clear();

                send_ack_packet(send_sock_fd,*(sockaddr*)&recv_addr, recv_packet.get_transport_src(),next_expected_seq_no);

                break;
            }
            else if (base_type == net::BASE_PACKET_TYPE::DATA)
            {
                if (!first_data_packet_received)
                {
                    first_data_packet_time = most_recent_packet_time;
                    first_data_packet_received = true;
                }

                if (recv_packet.get_seq_no() < window_start_seq_no)
                    continue;

                auto inserted_packet = recv_window.insert(std::move(recv_packet));
                const auto & data_packet = *inserted_packet.first;
                
                // Verify that the dest IP in the packet matches the IP of this machine
                sockaddr data_packet_dest = data_packet.get_transport_dest();
                sockaddr_in data_packet_dest_addr = *(sockaddr_in*)&data_packet_dest;
                if (data_packet_dest_addr.sin_port != recv_addr.sin_port || 
                    data_packet_dest_addr.sin_addr.s_addr != recv_addr.sin_addr.s_addr)
                    throw std::runtime_error("request_recv_task local/destination address mismatch\n");

                next_expected_seq_no = net::get_next_expected_seq_no(recv_window, window_start_seq_no);
                send_ack_packet(send_sock_fd,*(sockaddr*)&recv_addr, data_packet.get_transport_src(),next_expected_seq_no);

                if (inserted_packet.second == false)
                {
                    std::cout << "Duplicate packet received. Sequence number: " << data_packet.get_seq_no() << '\n';
                    continue;
                }
                else if (recv_window.size() > recv_window_size)
                {
                    throw std::runtime_error("requester_recv_task window overflow\n");
                }

                ++data_packets_received;

                const auto & payload_chunk = data_packet.get_payload();

                std::cout << "Packet received. Arrival time (ms): " <<
                    std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now() - 
                        first_data_packet_time).count() <<
                    "; Src addr: " << net::sockaddr_to_str(src_addr) <<
                    "; Seq no: " << data_packet.get_seq_no() <<
                    "; Payload size: " << payload_chunk.size() <<
                    "; First 4 bytes of payload: \"";

                std::cout << std::string(payload_chunk.begin(), payload_chunk.begin() + 
                    std::min(payload_chunk.size(),std::size_t(4)));
                std::cout << "\"\n";

                if (recv_window.size() == recv_window_size)
                {
                    const auto & start_packet = *recv_window.begin();
                    const auto & last_packet = *recv_window.rbegin();

                    if (next_expected_seq_no != last_packet.get_seq_no() + last_packet.get_payload_size() ||
                        window_start_seq_no != start_packet.get_seq_no())
                        throw std::runtime_error("requester_recv_task window full but sequence numbers don't match\n");

                    append_window_packets(recv_window, file_chunk);
                    recv_window.clear();

                    window_start_seq_no = next_expected_seq_no;
                }
            }
        }
        else if (most_recent_packet_time + net::REQUESTER_RECV_TIMEOUT < std::chrono::system_clock::now())
        {
            // need to account for a data ack lost on the way to the sender
            throw std::runtime_error("requester_recv_task timed out after no packets received for " +
                std::to_string(net::REQUESTER_RECV_TIMEOUT.count()) + " ms\n");
        }
    }

    std::cout << "\nEnd packet received from sender:\n";
    std::cout << "Total data packets received: " << data_packets_received << '\n';
    std::cout << "Total data bytes received: " << file_chunk.size() << '\n';
    const auto test_duration = end_packet_time - first_data_packet_time;
    const double packets_per_us = (double) data_packets_received /
        (double) std::chrono::duration_cast<std::chrono::microseconds>(test_duration).count();
    std::cout << "Average packets per second: " << packets_per_us * 1000000.0 << '\n';
    std::cout << "Test duration (ms): " << std::chrono::duration_cast<std::chrono::milliseconds>(test_duration).count() << '\n';

    return file_chunk;
}

int main(int argc, char * argv[])
{
    uint16_t requester_port{0}, emulator_port{0};
    uint32_t requester_window_size{0};
    std::string filename;
    std::string emulator_hostname;

    {
        po::options_description desc;
        try
        {
            desc.add_options()
                (",p", po::value<uint16_t>(&requester_port)->required(), "requester port")
                (",f", po::value<std::string>(&emulator_hostname)->required(), "emulator hostname")
                (",h", po::value<uint16_t>(&emulator_port)->required(), "emulator port")
                (",o", po::value<std::string>(&filename)->required(), "requested file name")
                (",w", po::value<uint32_t>(&requester_window_size)->required(), "requester window size");

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
    if (requester_port < 1024)
    {
        std::cerr << "Invalid requester port number. Must be > 1023\n";
        return -1;
    }
    if (requester_window_size < 1)
    {
        std::cerr << "Invalid requester window size. Must be > 0\n";
        return -1;
    }

    auto job_queue = generate_job_queue(filename);

    auto recv_fd_addr = net::bind_recv_local(requester_port);
    auto & recv_sock_fd = recv_fd_addr.first;
    auto & requester_recv_addr = recv_fd_addr.second;

    // initialize UDP send socket
    const net::sock_fd send_sock_fd(socket(AF_INET, SOCK_DGRAM, 0));
    net::set_buffer_size(send_sock_fd.get());
    if (send_sock_fd.get() < 0)
    {
        std::cerr << "Could not initialize send socket\n";
        return -1;
    }

    // run jobs
    std::vector< uint8_t > file_data;
    for (const auto & job : job_queue)
    {
        auto hostname = std::get<2>(job);
        auto sender_port = std::get<3>(job);

        auto ip_addr = net::hostname_to_ip4(hostname,sender_port);
        if (!ip_addr)
        {
            std::cerr << "Could not resolve hostname/sender_port: " << hostname << '/' << sender_port << '\n';
            return -1;
        }
        else
        {
            std::cerr << "Resolved hostname/sender_port: " << hostname << '/' << sender_port << '\n';
        }

        // dispatch recv thread
        auto recv_thread = std::async(std::launch::async, requester_recv_task, std::ref(recv_sock_fd), *(sockaddr_in*)&requester_recv_addr,
            std::ref(send_sock_fd), requester_window_size);

        // dispatch request packet
        TransportPacket request_pkt(net::BASE_PACKET_TYPE::REQUEST, TransportPacket::TRANSPORT_PRIORITY::HIGH, 
            *((sockaddr*)&requester_recv_addr), *ip_addr->ai_addr,requester_window_size);
        auto bytes_sent = request_pkt.send_packet(send_sock_fd);

        std::cerr << "UDP request packet sent. Total bytes sent: " << bytes_sent << "; Dest addr: " << 
            net::sockaddr_to_str(*ip_addr->ai_addr) << '\n';

        try
        {
            auto file_chunk = recv_thread.get();
            std::copy(file_chunk.begin(), file_chunk.end(), std::back_inserter(file_data));
        }
        catch (std::runtime_error & e)
        {
            std::cerr << "Receiver task failed: " << e.what() << '\n';
            return -1;
        }
    }

    const std::string assembled_filename(std::string("_") + filename);
    std::ofstream assembled_file(assembled_filename, std::ofstream::trunc | std::ofstream::binary);
    if (!assembled_file.is_open())
    {
        std::cerr << "Error: could not open file for writing\n";
        return -1;
    }
    std::copy(file_data.begin(), file_data.end(), std::ostream_iterator<uint8_t>(assembled_file));

    std::cerr << "\nRequester terminated normally. Joined file written to: " << assembled_filename << '\n';

    return 0;
}
