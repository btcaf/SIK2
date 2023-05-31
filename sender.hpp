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
           uint64_t rexmit_time, std::string _reply_message);

    ~Sender();

    void run();

private:
    void main_sender();

    /**
     * Funkcje na potrzeby obsługi wyjątków.
     */
    void listener_wrap();
    void rexmit_sender_wrap();
    void reply_sender_wrap();

    /**
     * Kod wątku odbierającego komunikaty odbiorników.
     */
    void listener();

    /**
     * Kod wątku wysyłającego retransmisje.
     */
    void rexmit_sender();

    /**
     * Kod wątku wysyłającego komunikaty REPLY.
     */
    void reply_sender();

    static const size_t BUFFER_SIZE = 1024;
    static const size_t HEADER_SIZE = 16;
    static const size_t HEADER_ELEMENT_SIZE = 8;
    static const size_t REXMIT_HEADER_LEN = 14;

    const uint64_t session_id = time(NULL);
    const size_t packet_size;
    const size_t full_packet_size = packet_size + HEADER_SIZE;
    struct sockaddr_in multicast_address;
    int data_socket_fd;
    int ctrl_socket_fd;
    size_t queue_size;
    uint64_t rexmit_time;
    uint64_t packet_num = 0;

    std::mutex mut;
    boost::circular_buffer<byte_t> fifo =
            boost::circular_buffer<byte_t>(queue_size);

    const std::string reply_message;
    std::set<uint64_t> rexmit_requests;

    std::atomic_bool is_main_finished = false;
    std::atomic_bool is_listener_finished = false;
    std::exception_ptr exception_to_throw = nullptr;

    Blocking_Queue<struct sockaddr_in> reply_queue;
    Blocking_Queue<uint64_t> rexmit_queue;

    // zwalniane w destruktorze
    byte_t *packet_buf = new byte_t[full_packet_size];
    byte_t *rexmit_packet_buf = new byte_t[full_packet_size];
    char *message_buf = new char[BUFFER_SIZE];
};

#endif //SIKRADIO_SENDER_HPP
