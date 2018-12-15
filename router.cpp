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
/*
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
*/
int main(int argc, char * argv[])
{

}