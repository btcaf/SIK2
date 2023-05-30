#include "sender.hpp"
#include "common.hpp"

#include <unistd.h>
#include <cstring>
#include <stdexcept>
#include <thread>
#include <regex>
#include <utility>

Sender::Sender(size_t _packet_size,
               struct sockaddr_in _receiver_address, int _data_socket_fd,
               int _ctrl_socket_fd, size_t queue_size, uint64_t rexmit_time,
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

        memcpy(packet_buf, &be_session_id, HEADER_ELEMENT_SIZE);
        memcpy(&packet_buf[HEADER_ELEMENT_SIZE], &be_first_byte_num,
               HEADER_ELEMENT_SIZE);
        size_t size = std::fread(&packet_buf[HEADER_SIZE], sizeof(byte_t),
                                 packet_size, stdin);
        if (size < packet_size) {
            break;
        }

        send_message(packet_buf);

        {
            std::lock_guard<std::mutex> lock{mut};
            for (size_t i = 0; i < packet_size; ++i) {
                fifo.push_back(packet_buf[HEADER_SIZE + i]);
            }
            packet_num += packet_size;
        }

    }
    is_main_finished = true;
    listener.join();
}

void Sender::send_message(byte_t *buffer) {
    ssize_t sent_bytes = sendto(data_socket_fd, buffer, full_packet_size, 0,
                                (struct sockaddr *) (&multicast_address),
                                sizeof(multicast_address));

    if (sent_bytes < 0 || (size_t) sent_bytes < full_packet_size) {
        throw std::runtime_error("sendto() failed");
    }
}

void Sender::listener() {
    std::thread rexmit_sender{&Sender::rexmit_sender, this};
    std::thread reply_sender{&Sender::reply_sender, this};
    while (true) {
        // sprawdź, czy nie kończyć, jeśli tak to poczekaj na wysyłające wątki
        if (is_main_finished) {
            is_listener_finished = true;

            // przekazujemy dane do kolejki, aby odblokować potencjalnie
            // czekające wątki
            struct sockaddr_in dummy_address;
            memset(&dummy_address, 0, sizeof(dummy_address));
            reply_queue.push(dummy_address);
            rexmit_queue.push(0);

            reply_sender.join();
            rexmit_sender.join();
            return;
        }

        uint64_t start_time = time_since_epoch_ms();
        while (true) {
            uint64_t curr_time = time_since_epoch_ms();
            if (curr_time > start_time + rexmit_time) {
                break;
            }

            struct sockaddr_in receiver_address;
            socklen_t address_length = (socklen_t) sizeof(receiver_address);

            struct timeval timeout;
            uint64_t timeout_ms = start_time + rexmit_time - curr_time;

            timeout.tv_sec = timeout_ms / 1000;
            timeout.tv_usec = (timeout_ms % 1000) * 1000;

            if (setsockopt(ctrl_socket_fd, SOL_SOCKET, SO_RCVTIMEO,
                           (const char *) &timeout, sizeof timeout) < 0) {
                throw std::runtime_error("Error configuring socket");
            }

            ssize_t read_bytes = recvfrom(ctrl_socket_fd, message_buf,
                                          BUFFER_SIZE,
                                          0, (struct sockaddr *)
                                                  &receiver_address,
                                                  &address_length);
            if (read_bytes < 0) {
                throw std::runtime_error("recvfrom() failed");
            }
            message_buf[read_bytes] = '\0';

            // jeśli LOOKUP, zleć odpowiedź
            if (strcmp(message_buf, "ZERO_SEVEN_COME_IN\n") == 0) {
                reply_queue.push(receiver_address);
            }

            // jeśli REXMIT, zapisz prośbę
            if (std::regex_match(message_buf,
                     std::regex(R"(LOUDER_PLEASE [0-9]+(,[0-9]+)*\n)"))) {
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

        // zleć wysyłanie retransmisji
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

            memcpy(rexmit_packet_buf, &be_session_id, HEADER_ELEMENT_SIZE);
            memcpy(&rexmit_packet_buf[HEADER_ELEMENT_SIZE], &be_first_byte_num,
                   HEADER_ELEMENT_SIZE);

            for (size_t i = 0; i < packet_size; ++i) {
                rexmit_packet_buf[HEADER_SIZE + i] =
                        fifo[packet_to_send - first_packet + i];
            }

            send_message(rexmit_packet_buf);
        }
    }
}

void Sender::reply_sender() {
    while (true) {
        struct sockaddr_in receiver_address = reply_queue.pop();
        if (is_listener_finished) {
            return;
        }

        ssize_t sent_bytes = sendto(ctrl_socket_fd, reply_message.c_str(),
                                    reply_message.length(), 0,
                                    (struct sockaddr *) (&receiver_address),
                                    sizeof(receiver_address));

        if (sent_bytes < 0 || (size_t) sent_bytes < reply_message.length()) {
            throw std::runtime_error("sendto() failed");
        }
    }
}