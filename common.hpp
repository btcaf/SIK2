#ifndef SIKRADIO_COMMON_HPP
#define SIKRADIO_COMMON_HPP

#include <cstdint>
#include <string>

int bind_socket(uint16_t port);

struct sockaddr_in get_address(const std::string& host, uint16_t port, bool check_multicast);

#endif //SIKRADIO_COMMON_HPP
