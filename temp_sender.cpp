#include "temp_sender.hpp"
#include "common.hpp"

#include <stdexcept>
#include <sys/socket.h>
#include <netdb.h>
#include <cstring>
#include <unistd.h>
#include <chrono>

Temp_Sender::Temp_Sender(uint64_t _data_port, size_t _packet_size,
                         std::string _name,
                         std::string _multicast_address_string,
                         uint16_t _ctrl_port, size_t _queue_size,
                uint64_t _rexmit_time)
            : data_port(_data_port),
              packet_size(_packet_size),
              name(std::move(_name)),
              multicast_address_string(std::move(_multicast_address_string)),
              ctrl_port(_ctrl_port),
              queue_size(_queue_size),
              rexmit_time(_rexmit_time) {}

Sender Temp_Sender::make_sender() {
    struct sockaddr_in multicast_address = get_address(multicast_address_string,
            data_port, true);

    // zamykane w destruktorze klasy Sender
    int data_socket_fd = socket(PF_INET, SOCK_DGRAM, 0);
    if (data_socket_fd < 0) {
        throw std::runtime_error("Error creating socket");
    }

    int ctrl_socket_fd = bind_socket(ctrl_port, UDP, false);

    std::string reply_message = "BOREWICZ_HERE " + multicast_address_string +
            " " + std::to_string(data_port) + " " + name + "\n";

    return {packet_size, multicast_address, data_socket_fd, ctrl_socket_fd,
            queue_size, rexmit_time, reply_message};
}