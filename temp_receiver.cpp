#include "temp_receiver.hpp"
#include "common.hpp"

#include <netdb.h>
#include <cstring>
#include <utility>
#include <fcntl.h>

Temp_Receiver::Temp_Receiver(std::string _discover_address_string, uint16_t _ctrl_port,
            uint16_t _ui_port, size_t _buffer_size, uint64_t _rexmit_time,
            std::string _favorite_name)
            : discover_address_string(std::move(_discover_address_string)),
              ctrl_port(_ctrl_port),
              ui_port(_ui_port),
              buffer_size(_buffer_size),
              rexmit_time(_rexmit_time),
              favorite_name(std::move(_favorite_name)) {}

Receiver Temp_Receiver::make_receiver() {
    struct sockaddr_in discover_address = get_address(discover_address_string, ctrl_port, false);
    int lookup_socket_fd = bind_socket(ctrl_port, UDP, true, false);
    if (fcntl(lookup_socket_fd, F_SETFL, O_NONBLOCK) < 0) {
        throw std::runtime_error("Error configuring socket");
    }
    int optval = 1;
    if (setsockopt(lookup_socket_fd, SOL_SOCKET, SO_BROADCAST, &optval, sizeof(optval))) {
        throw std::runtime_error("Error configuring socket");
    }

    int reply_socket_fd = bind_socket(ctrl_port, UDP, true, false);
    struct timeval timeout;

    timeout.tv_sec = 1;
    timeout.tv_usec = 0;

    if (setsockopt(reply_socket_fd, SOL_SOCKET, SO_RCVTIMEO,
                     (const char *) &timeout, sizeof timeout) < 0) {
        throw std::runtime_error("Error configuring socket");
    }

    int ui_socket_fd = bind_socket(ui_port, TCP, false, false);

    return {discover_address, lookup_socket_fd, reply_socket_fd, ui_socket_fd, buffer_size, rexmit_time,
            favorite_name};
}