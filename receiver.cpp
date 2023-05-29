#include "receiver.hpp"
#include "common.hpp"
#include <iostream>
#include <unistd.h>
#include <thread>
#include <cstring>
#include <chrono>
#include <utility>
#include <regex>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

Receiver::Receiver(struct sockaddr_in _discover_address, int _lookup_socket_fd, int _reply_socket_fd, int _ui_socket_fd,
                   size_t _buffer_size, uint64_t _rexmit_time, std::string _favorite_name)
        : discover_address(_discover_address),
          lookup_socket_fd(_lookup_socket_fd),
          reply_socket_fd(_reply_socket_fd),
          ui_socket_fd(_ui_socket_fd),
          buffer_size(_buffer_size),
          rexmit_time(_rexmit_time),
          favorite_name(std::move(_favorite_name)) {}

Receiver::~Receiver() {
    delete[] buffer;
    // jeśli się nie uda, to nic z tym nie zrobimy
    close(lookup_socket_fd);
    close(reply_socket_fd);
    close(ui_socket_fd);
    // close(data_socket_fd);
}

[[noreturn]] void Receiver::run() {
    std::thread lookuper{&Receiver::lookuper, this};
    std::thread listener{&Receiver::listener, this};
    std::thread data_receiver{&Receiver::data_receiver, this};
    while (true) {

    }
}

[[noreturn]] void Receiver::lookuper() {
    while (true) {
        uint64_t time = time_since_epoch_ms();

        {
            std::lock_guard<std::mutex> lock{mut};
            // TODO słabe
            std::erase_if(stations, [time](const auto& item) {
                auto const& [key, value] = item;
                return value + 20 < time;
            }); // TODO odtwarzanie innej
        }


        char const *msg = "ZERO_SEVEN_COME_IN\n";
        ssize_t sent_bytes = sendto(lookup_socket_fd, msg, 19, 0, (struct sockaddr*) &discover_address, sizeof(discover_address));
        // TODO błąd?

        uint64_t time_diff = time_since_epoch_ms() - time;
        if (time_diff > 5000) { // raczej nie powinno się wydarzyć
            continue;
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(5000 - time_diff));
    }
}

[[noreturn]] void Receiver::listener() {
    while (true) {
        struct sockaddr_in received_address;
        socklen_t address_length = (socklen_t) sizeof(received_address);
        char reply_buf[100];

        ssize_t read_bytes = recvfrom(reply_socket_fd, reply_buf, 100, 0, (struct sockaddr *) &received_address, &address_length);
        if (read_bytes < 0) {
            continue;
        }
        reply_buf[read_bytes] = '\0';
        if (std::regex_match(reply_buf, std::regex(R"(BOREWICZ_HERE [0-9\.]+ [0-9]+ [\x21-\x7F][\x20-\x7F]*[\x21-\x7F]|[\x21-\x7F]\\n)"))) {
            std::string reply(reply_buf);
            reply.erase(0, 14);
            std::istringstream reply_stream(reply);
            std::string multicast_address;
            std::string port_string;
            std::string name;

            std::getline(reply_stream, multicast_address, ' ');
            std::getline(reply_stream, port_string, ' ');
            std::getline(reply_stream, name, ' ');

            if (name.length() > 64) {
                continue;
            }

            unsigned long port = std::stoul(port_string);
            if (port > UINT16_MAX) {
                continue;
            }

            struct ip_mreq ip_mreq;
            ip_mreq.imr_interface.s_addr = htonl(INADDR_ANY);
            if (inet_aton(multicast_address.c_str(), &ip_mreq.imr_multiaddr) == 0) {
                continue;
            }

            Station_Data station_data;
            station_data.name = name;
            station_data.ip_mreq = ip_mreq;
            station_data.port = port;
            station_data.address = received_address;
            station_data.address_length = address_length;

            std::lock_guard<std::mutex> lock{mut};
            bool flag = true;
            if (name == favorite_name) {
                for (auto const &[key, value]: stations) {
                    if (key.name == name) {
                        flag = false;
                    }
                }
                if (flag) {
                    curr_station = station_data; // TODO porty
                }
            }
            if (favorite_name.empty() && stations.empty()) {
                curr_station = station_data;
            }
            stations[station_data] = time_since_epoch_ms();
        }
    }
}

[[noreturn]] void Receiver::data_receiver() {
    std::thread writer{&Receiver::writer, this};
    while (true) {
        if (!receive_message()) {
            continue;
        }

        uint64_t first_byte_num = 0;
        memcpy(&first_byte_num, &msg_buffer[8], 8);
        first_byte_num = be64toh(first_byte_num);

        // przyjmujemy niezmiennik:
        // next_to_receive - max_packets <= next_to_print <= next_to_receive
        // (wynik odejmowania powyżej może być ujemny)
        // w ten sposób wiemy, że paczkę nr next_to_print rzeczywiście
        // będziemy mogli wypisać (tj. nie została nadpisana)

        // mamy pięć przypadków:

        // 1. first_byte_num < byte0: porzucamy paczkę
        if (first_byte_num < byte0) {
            continue;
        }

        bool notify = false;
        {
            std::lock_guard<std::mutex> lock{mut};

            // 2. Aktualna paczka nie mieści się w buforze: porzucamy
            // paczkę.
            uint64_t curr_packet = (first_byte_num - byte0) / packet_size;
            if (curr_packet + max_packets < next_to_receive) {
                continue;
            }
            // 3. Aktualna paczka mieści się w buforze, ale została już
            // wypisana paczka późniejsza. W takiej sytuacji nie mamy po co
            // wpisywać paczki do bufora, ale musimy ją potraktować jako
            // odebraną pod kątem wypisywania komunikatów o brakujących
            // paczkach.
            if (curr_packet < next_to_print) {
                received_packets.insert(curr_packet);
                print_missing_packets(curr_packet);
                continue;
            }
            // 4. Aktualna paczka jest starsza niż najnowsza odebrana,
            // ale może jeszcze zostać wypisana
            if (curr_packet < next_to_receive) {
                memcpy(&buffer[curr_packet % max_packets * packet_size],
                       &msg_buffer[16], packet_size);

                received_packets.insert(curr_packet);
                print_missing_packets(curr_packet);
                continue;
            }
            // 5. Aktualna paczka jest najnowszą z dotychczas odebranych.
            memcpy(&buffer[curr_packet % max_packets * packet_size],
                   &msg_buffer[16], packet_size);

            uint64_t old_next_to_receive = next_to_receive;
            next_to_receive = curr_packet + 1;

            // zapewniamy niezmiennik
            uint64_t old_next_to_print = next_to_print;
            if (next_to_print + max_packets < next_to_receive) {
                next_to_print = next_to_receive - max_packets + 1;
            }

            received_packets.insert(curr_packet);
            clear_old_packets();
            print_missing_packets(curr_packet);

            // powiadamiamy piszący wątek, jeśli 3 / 4 bufora zostało
            // zapełnione
            if (!writing && first_byte_num + packet_size - 1 >=
                            byte0 + 3 * buffer_size / 4) {
                writing = true;
                notify = true;
            }

            // powiadamiamy piszący wątek, jeśli czekał na nową paczkę
            if (writing && old_next_to_receive == old_next_to_print) {
                notify = true;
            }
        }
        if (notify) {
            cv_writing.notify_one();
        }
    }
}

/**
 * Kod wątku wypisującego dane binarne na standardowe wyjście.
 */
[[noreturn]] void Receiver::writer() {

    while (true) {
        // czeka na możliwość pisania
        {
            std::unique_lock<std::mutex> lock(mut);
            cv_writing.wait(lock, [this] { return writing; });
        }
        while (true) {
            {
                std::unique_lock<std::mutex> lock(mut);
                if (!writing) {
                    break;
                }
                // czeka na następną paczkę lub na nową sesję
                if (next_to_print == next_to_receive) {
                    cv_writing.wait(lock, [this]
                    { return next_to_receive > next_to_print; });
                    // jeśli nie może pisać, to zaczęła się nowa sesja,
                    // więc powinien z powrotem poczekać na taką możliwość
                    // (zapełnienie bufora w 3 / 4)
                    if (!writing) {
                        break;
                    }
                }
                // wypisujemy tylko te fragmenty bufora, w których jest
                // odebrana paczka
                if (received_packets.contains(next_to_print)) {
                    std::fwrite(&buffer[next_to_print %
                                        max_packets * packet_size], 1,
                                packet_size, stdout);
                    fflush(stdout);
                }
                ++next_to_print;
            }
        }
    }
}

void Receiver::print_missing_packets(uint64_t curr_packet) {
    // wypisujemy tylko paczki, na które jest miejsce w buforze
    for (uint64_t i = next_to_receive > max_packets
                      ? next_to_receive - max_packets
                      : 0; i < curr_packet; ++i) {
        if (!received_packets.contains(i)) {
            std::cerr << "MISSING: BEFORE "
                      << byte0 + packet_size * curr_packet
                      << " EXPECTED "
                      << byte0 + packet_size * i
                      << "\n";
        }
    }
}

/**
 * Usuwa informacje o tych odebranych paczkach, które zostały usunięte
 * z bufora (możliwe, że nie zostały jeszcze nadpisane, ale ich miejsce
 * jest zarezerwowane dla kolejnych paczek).
 */
void Receiver::clear_old_packets() {
    std::erase_if(received_packets, [this](auto const &x)
    { return x + max_packets < next_to_receive; });
}

/**
 * Zwraca true, jeśli wiadomość została poprawnie odczytana (i zapisuje ją
 * w msg_buffer) i false, jeśli została porzucona.
 */
bool Receiver::receive_message() {
    uint64_t new_session_id;

    struct sockaddr_in received_address;
    socklen_t address_length = (socklen_t) sizeof(received_address);

    ssize_t read_bytes = safe_recvfrom(data_socket_fd, &new_session_id, 8,
                                       MSG_PEEK | MSG_TRUNC, (struct sockaddr *)
                                               &received_address, &address_length, 0);

    new_session_id = be64toh(new_session_id);

    // porzucamy paczkę, jeśli przyszła ze złego adresu lub jest ze
    // starszej sesji (przesyłamy po UDP, więc nie musimy wczytywać
    // całej)
    if (received_address.sin_addr.s_addr != sender_address
        || new_session_id < session_id) {
        safe_recvfrom(data_socket_fd, &new_session_id, 8, 0, (struct sockaddr *)
                &received_address, &address_length, 0);
        return false;
    }

    if (new_session_id > session_id) {
        session_id = new_session_id;
        {
            std::lock_guard<std::mutex> lock{mut};
            writing = false;
            // next_to_print zmieniamy na 0, żeby warunek piszącego,
            // który czeka na zmiennej był spełniony
            next_to_print = 0;
        }
        // budzimy piszącego, który może czekać na kolejną paczkę
        // writing jest false, więc piszący wróci na początek pętli
        cv_writing.notify_one();
        next_to_receive = 0;
        received_packets.clear();
        packet_size = (size_t) read_bytes - 16;
        max_packets = buffer_size / packet_size;
        // zainicjowaliśmy msg_buffer na NULL, więc możemy tak zrobić
        delete[] msg_buffer;
        msg_buffer = new byte_t[packet_size + 16];
        safe_recvfrom(data_socket_fd, msg_buffer, packet_size + 16, 0,
                      (struct sockaddr *) &received_address,
                      &address_length, packet_size + 16);
        memcpy(&byte0, &msg_buffer[8], 8);
        byte0 = be64toh(byte0);
    } else {
        safe_recvfrom(data_socket_fd, msg_buffer, packet_size + 16, 0,
                      (struct sockaddr *) &received_address,
                      &address_length, packet_size + 16);
    }

    return true;
}