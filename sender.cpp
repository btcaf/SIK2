#include "sender.hpp"

#include <unistd.h>
#include <cstring>
#include <stdexcept>
#include <thread>
#include <regex>
#include <utility>

Sender::Sender(size_t _packet_size,
               struct sockaddr_in _receiver_address, int _data_socket_fd,
               int _ctrl_socket_fd, size_t queue_size, std::chrono::milliseconds rexmit_time,
               std::string _reply_message)
        : packet_size(_packet_size),
          multicast_address(_receiver_address),
          data_socket_fd(_data_socket_fd),
          ctrl_socket_fd(_ctrl_socket_fd),
          queue_size(queue_size),
          rexmit_time(rexmit_time),
          reply_message(std::move(_reply_message)) {}

Sender::~Sender() {
    delete[] packet_buf;
    delete[] rexmit_packet_buf;
    delete[] message_buf;
    // jeśli się nie uda, to nic z tym nie zrobimy
    close(data_socket_fd);
    close(ctrl_socket_fd);
}

void Sender::run() {
    std::thread listener{&Sender::listener, this};
    while (true) {
        // konwersja na sieciowy porządek bajtów
        uint64_t be_session_id = htobe64(session_id);

        uint64_t be_first_byte_num;
        {
            std::lock_guard<std::mutex> lock{mut};
            be_first_byte_num = htobe64(packet_num);
        }

        memcpy(packet_buf, &be_session_id, 8);
        memcpy(&packet_buf[8], &be_first_byte_num, 8);
        size_t size = std::fread(&packet_buf[16], 1, packet_size, stdin);
        if (size < packet_size) {
            break;
        }

        send_message();

        {
            std::lock_guard<std::mutex> lock{mut};
            for (size_t i = 0; i < packet_size; ++i) {
                fifo.push_back(packet_buf[16 + i]);
            }
            packet_num += packet_size;
        }

    }
    is_main_finished = true;
    listener.join();
}

void Sender::send_message() {
    ssize_t sent_bytes = sendto(data_socket_fd, packet_buf, packet_size + 16, 0,
                                (struct sockaddr *) (&multicast_address),
                                sizeof(multicast_address));

    if (sent_bytes < 0 || (size_t) sent_bytes < packet_size + 16) {
        throw std::runtime_error("sendto() failed"); // TODO mega sus
    }
}

void Sender::listener() {
    // puść wysyłacze
    std::thread rexmit_sender{&Sender::rexmit_sender, this};
    std::thread reply_sender{&Sender::reply_sender, this};
    while (true) {
        // sprawdź czy nie kończyć, jeśli tak to wait na wysyłacze
        if (is_main_finished) {
            is_listener_finished = true;

            struct sockaddr_in dummy_address;
            memset(&dummy_address, 0, sizeof(dummy_address));
            reply_queue.push(dummy_address);
            rexmit_queue.push(0);

            reply_sender.join();
            rexmit_sender.join();
            return;
        }

        auto start_time = std::chrono::steady_clock::now();
        // TODO while czas < rexmit_time
        while (true) {
            auto curr_time = std::chrono::steady_clock::now();
            if (curr_time > start_time + rexmit_time) {
                break;
            }
            // TODO odbierz
            struct sockaddr_in receiver_address;
            socklen_t address_length = (socklen_t) sizeof(receiver_address);

            struct timeval timeout;
            auto to_ms =
                    std::chrono::duration_cast<std::chrono::milliseconds>(
                            start_time + rexmit_time - curr_time
                    );;
            timeout.tv_sec = to_ms.count() / 1000;
            timeout.tv_usec = (to_ms.count() % 1000) * 1000;

            // TODO może błąd
            setsockopt(ctrl_socket_fd, SOL_SOCKET, SO_RCVTIMEO, (const char *) &timeout, sizeof timeout);

            ssize_t read_bytes = recvfrom(ctrl_socket_fd, message_buf, 65507,
                                          0, (struct sockaddr *)
                                                  &receiver_address, &address_length);
            if (read_bytes < 0) {
                continue;
            }
            message_buf[read_bytes] = '\0';

            // if lookup reply
            if (strcmp(message_buf, "ZERO_SEVEN_COME_IN\n") == 0) {
                reply_queue.push(receiver_address);
            }

            // if rexmit zapisz
            if (std::regex_match(message_buf, std::regex(R"(LOUDER_PLEASE [0-9]+(,[0-9]+)*\\n)"))) { // TODO spacje
                std::string msg(message_buf);
                msg.erase(0, 14);
                std::istringstream msg_stream(msg);
                std::string s;
                while (std::getline(msg_stream, s, ',')) {
                    uint64_t num = std::stoull(s);
                    if (num % packet_size == 0) {
                        rexmit_requests.insert(num);
                    }
                }
            }
        }

        // zleć wysyłanie rexmitów
        for (auto request: rexmit_requests) {
            rexmit_queue.push(request);
        }
        rexmit_requests.clear();
    }
}

void Sender::rexmit_sender() {
    while (true) {
        uint64_t packet_to_send = rexmit_queue.pop();
        if (is_listener_finished) {
            return;
        }

        {
            std::lock_guard<std::mutex> lock{mut};
            uint64_t first_packet = packet_num - fifo.size();
            if (packet_to_send < first_packet || packet_to_send >= packet_num) {
                continue;
            }
            uint64_t be_session_id = htobe64(session_id);
            uint64_t be_first_byte_num = htobe64(packet_to_send);

            memcpy(rexmit_packet_buf, &be_session_id, 8);
            memcpy(&rexmit_packet_buf[8], &be_first_byte_num, 8);

            for (size_t i = 0; i < packet_size; ++i) {
                rexmit_packet_buf[16 + i] = fifo[packet_to_send - first_packet + i];
            }

            ssize_t sent_bytes = sendto(data_socket_fd, rexmit_packet_buf, packet_size + 16, 0,
                                        (struct sockaddr *) (&multicast_address),
                                        sizeof(multicast_address));

            if (sent_bytes < 0 || (size_t) sent_bytes < packet_size + 16) {
                throw std::runtime_error("sendto() failed"); // TODO mega sus
            }
        }
        break;
    }
}

void Sender::reply_sender() {
    while (true) {
        struct sockaddr_in receiver_address = reply_queue.pop();
        if (is_listener_finished) {
            return;
        }

        ssize_t sent_bytes = sendto(ctrl_socket_fd, reply_message.c_str(), reply_message.length(), 0,
                                    (struct sockaddr *) (&receiver_address),
                                    sizeof(receiver_address));

        if (sent_bytes < 0 || (size_t) sent_bytes < reply_message.length()) {
            throw std::runtime_error("sendto() failed"); // TODO mega sus
        }
    }
}