#ifndef SIKRADIO_COMMON_HPP
#define SIKRADIO_COMMON_HPP

#include <cstdint>
#include <string>
#include <unistd.h>

typedef enum Protocol {
    UDP,
    TCP
} Protocol;

/**
 * Zaadaptowana funkcja bind_socket() z zajęć laboratoryjnych.
 */
int bind_socket(uint16_t port, Protocol protocol,
                bool reuse_port);

/**
 * Zaadaptowana funkcja get_address(host, port) z zajęć laboratoryjnych.
 */
struct sockaddr_in get_address(const std::string& host, uint16_t port,
        bool check_multicast);

uint64_t time_since_epoch_ms();

/**
 * Wrapper sendto rzucający wyjątek w przypadku błędu.
 */
ssize_t safe_sendto(int sockfd, const void *buf, size_t len, int flags,
                      const struct sockaddr *src_addr,
                      socklen_t addrlen, size_t min_expected);

#endif //SIKRADIO_COMMON_HPP
