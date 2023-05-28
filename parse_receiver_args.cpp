#include <boost/program_options.hpp>
#include <boost/multiprecision/cpp_int.hpp>
#include <regex>

#include "parse_receiver_args.hpp"

namespace po = boost::program_options;
namespace mp = boost::multiprecision;

Temp_Receiver parse_receiver_args(int argc, char *argv[]) {
    std::string discover_address;
    int32_t CTRL_PORT;
    int32_t UI_PORT;
    mp::int128_t BSIZE;
    mp::int128_t RTIME;
    std::string name;

    po::options_description desc("Program usage");
    desc.add_options()
            (
                    "discover-address,d",
                    po::value<std::string>(&discover_address)->default_value("255.255.255.255")
            )
            (
                    "control-port,C",
                    po::value<int32_t>(&CTRL_PORT)->default_value(39922)
            )
            (
                    "ui-port,U",
                    po::value<int32_t>(&CTRL_PORT)->default_value(19922)
            )
            (
                    "buffer-size,b",
                    po::value<mp::int128_t>(&BSIZE)->default_value(65536)
            )
            (
                    "retransmission-time,R",
                    po::value<mp::int128_t>(&RTIME)->default_value(250)
            )
            (
                    "name,n",
                    po::value<std::string>(&name)->default_value("")
            );

    po::variables_map vm;
    po::store(po::parse_command_line(argc, argv, desc), vm);

    po::notify(vm);

    if (CTRL_PORT < 0 || CTRL_PORT > 65535) {
        throw std::runtime_error("Invalid control port number");
    }

    if (UI_PORT < 0 || UI_PORT > 65535) {
        throw std::runtime_error("Invalid UI port number");
    }

    if (BSIZE <= 0 || BSIZE > SIZE_MAX) {
        throw std::runtime_error("Invalid buffer size");
    }

    if (RTIME <= 0 || RTIME > SIZE_MAX) { // TODO sus
        throw std::runtime_error("Invalid time");
    }

    if (!vm["name"].defaulted() && (name.length() > 64 ||
        !std::regex_match(name, std::regex(R"([\x21-\x7F][\x20-\x7F]*[\x21-\x7F]|[\x21-\x7F])")))) {
        throw std::runtime_error("Invalid name");
    }

    return {discover_address, static_cast<uint16_t>(CTRL_PORT), static_cast<uint16_t>(UI_PORT),
            static_cast<size_t>(BSIZE), static_cast<uint64_t>(RTIME), name};
}