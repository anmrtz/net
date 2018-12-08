#include "emulator.hpp"

#include <boost/program_options.hpp>

#include <iostream>
#include <queue>

namespace po = boost::program_options;

static std::queue<net::TransportPacket> high_priority_queue, med_priority_queue, low_priority_queue;

int main(int argc, char * argv[])
{
    uint16_t emulator_port{0}, queue_size{0};
    std::string forwarding_table_filename, log_filename;

    {
        po::options_description desc;
        try
        {
            desc.add_options()
                (",p", po::value<decltype(emulator_port)>(&emulator_port)->required(), "emulator port")
                (",q", po::value<decltype(queue_size)>(&queue_size)->required(), "queue size")
                (",f", po::value<decltype(forwarding_table_filename)>(&forwarding_table_filename)->required(), "forwarding table filename")
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

    return 0;
}
