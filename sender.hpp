#ifndef SIKRADIO_SENDER_HPP
#define SIKRADIO_SENDER_HPP

#include <cstdint>
#include <cstddef>
#include <ctime>
#include <netinet/in.h>
#include <string>
#include <chrono>
#include <atomic>
#include <set>
#include <boost/circular_buffer.hpp>
#include <mutex>
#include "blocking_queue.hpp"

using byte_t = uint8_t;

/**
 * Klasa realizująca nadawanie danych.
 */
class Sender {
public:
    Sender(size_t _packet_size,
           struct sockaddr_in _receiver_address, int _data_socket_fd,
           int _ctrl_socket_fd, size_t queue_size,
           std::chrono::milliseconds rexmit_time, std::string _reply_message);

    ~Sender();

    void run();

private:
    void send_message();

    void listener();

    void rexmit_sender();

    void reply_sender();

    const uint64_t session_id = time(NULL);
    const size_t packet_size;
    struct sockaddr_in multicast_address;
    int data_socket_fd;
    int ctrl_socket_fd;
    size_t queue_size;
    std::chrono::milliseconds rexmit_time;
    uint64_t packet_num = 0;

    std::mutex mut;
    boost::circular_buffer<byte_t> fifo = boost::circular_buffer<byte_t>(queue_size);

    const std::string reply_message;
    std::set<uint64_t> rexmit_requests;

    std::atomic_bool is_main_finished = false;
    std::atomic_bool is_listener_finished = false;
    Blocking_Queue<struct sockaddr_in> reply_queue;
    Blocking_Queue<uint64_t> rexmit_queue;

    // zwalniane w destruktorze
    byte_t *packet_buf = new byte_t[packet_size + 16];
    byte_t *rexmit_packet_buf = new byte_t[packet_size + 16];
    char *message_buf = new char[65508]; // TODO ogarnąć
};

#endif //SIKRADIO_SENDER_HPP
