#include <gtest/gtest.h>
#include <net.hpp>

#include <iostream>
#include <memory>

using namespace net;

static const BASE_PACKET_TYPE DEFAULT_PACKET_TYPE{BASE_PACKET_TYPE::DATA};
static const TransportPacket::TRANSPORT_PRIORITY DEFAULT_TRANSPORT_PRIORITY{TransportPacket::TRANSPORT_PRIORITY::HIGH};
static const std::vector<uint8_t> DUMMY_DATA{1,2,3,4};
static const uint32_t DEFAULT_SEQ_NO{50};
static uint32_t DEFAULT_SRC_IP{0xFFEEDDCC};
static const uint16_t DEFAULT_SRC_PORT{100};
static uint32_t DEFAULT_DEST_IP{0xCCDDEEFF};
static const uint16_t DEFAULT_DEST_PORT{200};

class TPD : public ::testing::Test
{
    public:

    void SetUp() override
    {
        DEFAULT_SRC_ADDR.sin_family = AF_INET;
        DEFAULT_SRC_ADDR.sin_port = DEFAULT_SRC_PORT;
        memcpy(&DEFAULT_SRC_IP, &DEFAULT_SRC_ADDR.sin_addr, sizeof(DEFAULT_SRC_ADDR.sin_addr));

        DEFAULT_DEST_ADDR.sin_family = AF_INET;
        DEFAULT_DEST_ADDR.sin_port = DEFAULT_DEST_PORT;
        memcpy(&DEFAULT_DEST_IP, &DEFAULT_DEST_ADDR.sin_addr, sizeof(DEFAULT_DEST_ADDR.sin_addr));

        m_tp = std::make_unique<TransportPacket>(DEFAULT_PACKET_TYPE, DEFAULT_TRANSPORT_PRIORITY, 
            *(sockaddr*)&DEFAULT_SRC_ADDR, *(sockaddr*)&DEFAULT_DEST_ADDR, DEFAULT_SEQ_NO, DUMMY_DATA);
    }

    void TearDown() override
    {
    }

    TransportPacket & TP()
    {
        return *m_tp;
    }

    private:

    std::unique_ptr<TransportPacket> m_tp;
    sockaddr_in DEFAULT_SRC_ADDR{0};
    sockaddr_in DEFAULT_DEST_ADDR{0};
};

TEST(address_handling, hostname_to_ip4)
{
    auto addr =  hostname_to_ip4("localhost", 55);

    EXPECT_NE(addr.get(), nullptr);
}

TEST(address_handling, sockaddr_to_string)
{
    auto addr =  hostname_to_ip4("localhost", 55);
    auto addr_str = sockaddr_to_str(*addr->ai_addr);

    EXPECT_EQ(addr_str, "127.0.0.1");
}

TEST_F(TPD, generate_tp)
{
    ASSERT_TRUE(TP() == TP());
    auto pl = TP().get_payload();
    EXPECT_TRUE(std::equal(pl.begin(),pl.end(),DUMMY_DATA.begin()));
    EXPECT_TRUE(TP().get_priority() == DEFAULT_TRANSPORT_PRIORITY);
    EXPECT_TRUE(TP().get_base_type() == DEFAULT_PACKET_TYPE);

    auto src_addr = TP().get_transport_src();
    auto dest_addr = TP().get_transport_dest();

    sockaddr_in * src_in = (sockaddr_in*)&src_addr;
    sockaddr_in * dest_in = (sockaddr_in*)&dest_addr;
    uint32_t parsed_src_ip, parsed_dest_ip;
    memcpy(&parsed_src_ip, &src_in->sin_addr, 4);
    memcpy(&parsed_dest_ip, &dest_in->sin_addr, 4);

    EXPECT_EQ(parsed_src_ip, DEFAULT_SRC_IP);
    EXPECT_EQ(src_in->sin_port, DEFAULT_SRC_PORT);
    EXPECT_EQ(parsed_dest_ip, DEFAULT_DEST_IP);
    EXPECT_EQ(dest_in->sin_port, DEFAULT_DEST_PORT);
}
