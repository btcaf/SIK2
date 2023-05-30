#include "common.hpp"

#include <stdexcept>
#include <unistd.h>
#include <sys/socket.h>
#include <netdb.h>
#include <cstring>
#include <chrono>

int bind_socket(uint16_t port, Protocol protocol, bool reuse) {
    int socket_fd;
    if (protocol == UDP) {
        socket_fd = socket(AF_INET, SOCK_DGRAM, 0);
    } else {
        socket_fd = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    }
    if (socket_fd < 0) {
        throw std::runtime_error("Error creating socket");
    }

    if (reuse) {
        int optval = 1;
        if (setsockopt(socket_fd, SOL_SOCKET, SO_REUSEPORT, &optval,
                       sizeof(optval)) < 0) {
            throw std::runtime_error("Error configuring socket");
        }

    }

    struct sockaddr_in server_address;
    server_address.sin_family = AF_INET;
    server_address.sin_addr.s_addr = htonl(INADDR_ANY);
    server_address.sin_port = htons(port);

    if (bind(socket_fd, (struct sockaddr *) &server_address,
             (socklen_t) sizeof(server_address)) < 0) {
        close(socket_fd);
        throw std::runtime_error("Error binding socket");
    }

    return socket_fd;
}

struct sockaddr_in get_address(const std::string& host, uint16_t port,
        bool check_multicast) {
    struct addrinfo hints;
    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = IPPROTO_UDP;

    struct addrinfo *address_result;
    if (getaddrinfo(host.c_str(), NULL, &hints,
                    &address_result) != 0) {
        throw std::runtime_error("Error translating address");
    }

    struct sockaddr_in address;
    address.sin_family = AF_INET;
    address.sin_addr.s_addr =
            ((struct sockaddr_in *)
                    (address_result->ai_addr))->sin_addr.s_addr;
    address.sin_port = htons(port);

    freeaddrinfo(address_result);

    if (check_multicast) {
        if ((ntohl(address.sin_addr.s_addr) & 0xF0000000) != 0xE0000000) {
            throw std::runtime_error("Not a multicast address");
        }
    }


    return address;
}

uint64_t time_since_epoch_ms() {
    return std::chrono::system_clock::now().time_since_epoch() /
           std::chrono::milliseconds(1);
}

ssize_t safe_recvfrom(int sockfd, void *buf, size_t len, int flags,
                             struct sockaddr *src_addr,
                             socklen_t *addrlen, size_t min_expected) {
    ssize_t read_bytes = recvfrom(sockfd, buf, len, flags, src_addr,
                                  addrlen);

    if (read_bytes < 0 || (size_t) read_bytes < min_expected) {
        throw std::runtime_error("recvfrom() failed");
    }

    return read_bytes;
}

ssize_t safe_sendto(int sockfd, const void *buf, size_t len, int flags,
                      const struct sockaddr *src_addr,
                      socklen_t addrlen, size_t min_expected) {
    ssize_t sent_bytes = sendto(sockfd, buf, len, flags, src_addr,
                                  addrlen);

    if (sent_bytes < 0 || (size_t) sent_bytes < min_expected) {
        throw std::runtime_error("sendto() failed");
    }

    return sent_bytes;
}