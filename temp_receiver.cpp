#include "temp_receiver.hpp"
#include "common.hpp"

#include <netdb.h>
#include <cstring>
#include <utility>
#include <fcntl.h>

Temp_Receiver::Temp_Receiver(std::string _discover_address_string,
                             uint16_t _ctrl_port, uint16_t _ui_port,
                             size_t _buffer_size, uint64_t _rexmit_time,
                             std::string _favorite_name)
            : discover_address_string(std::move(_discover_address_string)),
              ctrl_port(_ctrl_port),
              ui_port(_ui_port),
              buffer_size(_buffer_size),
              rexmit_time(_rexmit_time),
              favorite_name(std::move(_favorite_name)) {}

Receiver Temp_Receiver::make_receiver() {
    struct sockaddr_in discover_address = get_address(discover_address_string,
            ctrl_port, false);
    int lookup_socket_fd = bind_socket(0, UDP, false);
    int optval = 1;
    if (setsockopt(lookup_socket_fd, SOL_SOCKET, SO_BROADCAST,
                   &optval, sizeof(optval))) {
        throw std::runtime_error("Error configuring socket");
    }


    // ustawiamy timeout na przyjmowanie i odbieranie
    struct timeval timeout;
    timeout.tv_sec = TIMEOUT_MS / 1000;
    timeout.tv_usec = (TIMEOUT_MS % 1000) * 1000;;

    if (setsockopt(lookup_socket_fd, SOL_SOCKET, SO_RCVTIMEO,
                     (const char *) &timeout, sizeof timeout) < 0) {
        throw std::runtime_error("Error configuring socket");
    }
    if (setsockopt(lookup_socket_fd, SOL_SOCKET, SO_SNDTIMEO,
                   (const char *) &timeout, sizeof timeout) < 0) {
        throw std::runtime_error("Error configuring socket");
    }

    int rexmit_socket_fd = socket(PF_INET, SOCK_DGRAM, 0);
    if (rexmit_socket_fd < 0) {
        throw std::runtime_error("Error creating socket");
    }

    int ui_socket_fd = bind_socket(ui_port, TCP, true);

    return {discover_address, lookup_socket_fd,
            ui_socket_fd, buffer_size, rexmit_time, rexmit_socket_fd,
            ctrl_port, favorite_name};
}