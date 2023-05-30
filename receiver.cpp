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
#include <poll.h>
#include <fcntl.h>

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

[[noreturn]] void Receiver::gui_handler() {
    /**
     * Zaadaptowany kod z zajęć laboratoryjnych.
     */
    bool first_time[CONNECTIONS];

    struct pollfd poll_descriptors[CONNECTIONS];
    /* Inicjujemy tablicę z gniazdami klientów, poll_descriptors[0] to gniazdo centrali */
    for (size_t i = 0; i < CONNECTIONS; ++i) {
        poll_descriptors[i].fd = -1;
        poll_descriptors[i].events = POLLIN;
        poll_descriptors[i].revents = 0;
        first_time[i] = false;
    }
    size_t active_clients = 0;

    /* gniazdo centrali */
    poll_descriptors[0].fd = ui_socket_fd;

    if (listen(poll_descriptors[0].fd, QUEUE_LENGTH) < 0) {
        throw std::runtime_error("listen() failed");
    }

    poll_descriptors[1].fd = pipe_dsc[0];

    while (true) {
        {
            std::lock_guard<std::mutex> lock{mut};
            if (exception_to_throw) {
                std::rethrow_exception(exception_to_throw);
            }
        }
        ssize_t offset = 0;
        bool activated = false;
        bool update = false;
        for (auto & poll_descriptor : poll_descriptors) {
            poll_descriptor.revents = 0;
        }

        int poll_status = poll(poll_descriptors, CONNECTIONS, TIMEOUT);
        if (poll_status == -1) {
            throw std::runtime_error("poll() failed");
        } else if (poll_status > 0) {
            if (poll_descriptors[0].revents & POLLIN) {
                /* Przyjmuję nowe połączenie */
                int client_fd = accept(poll_descriptors[0].fd, NULL, NULL);
                if (client_fd < 0) {
                    continue;
                }

                if (fcntl(client_fd, F_SETFL, O_NONBLOCK) < 0) {
                    continue;
                }

                bool accepted = false;
                for (size_t i = 2; i < CONNECTIONS; ++i) {
                    if (poll_descriptors[i].fd == -1) {
                        poll_descriptors[i].fd = client_fd;
                        poll_descriptors[i].events = POLLIN;
                        active_clients++;
                        accepted = true;
                        first_time[i] = true;
                        break;
                    }
                }
                if (!accepted) {
                    if (close(client_fd) < 0) {
                        throw std::runtime_error("Error closing socket");
                    }
                    std::cerr << "Too many clients\n";
                }
            }
            if (poll_descriptors[1].revents & POLLIN) {
                char buf[update_message.length() + 1];
                ssize_t received_bytes = read(poll_descriptors[1].fd, buf, update_message.length());
                if (received_bytes < 0) {
                    throw std::runtime_error("Receiving from pipe failed");
                }
                buf[received_bytes] = '\0';
                if (strcmp(buf, update_message.c_str()) != 0) {
                    throw std::runtime_error("Incorrect message read");
                }
                update = true;
            }
            for (size_t i = 2; i < CONNECTIONS; ++i) {
                if (poll_descriptors[i].fd != -1 && (poll_descriptors[i].revents & (POLLIN | POLLERR))) {
                    char buf[3];
                    ssize_t received_bytes = read(poll_descriptors[i].fd, buf, 3);
                    if (received_bytes <= 0) { // błąd lub zakończenie połączenia
                        if (close(poll_descriptors[i].fd) < 0) {
                            throw std::runtime_error("Error closing socket");
                        }
                        poll_descriptors[i].fd = -1;
                        active_clients -= 1;
                    } else {
                        if (received_bytes >= 3 && buf[0] == '\033' && buf[1] == '[') {
                            if (buf[2] == 'A') {
                                --offset;
                            } else if (buf[2] == 'B') {
                                ++offset;
                                activated = true;
                            }
                        }
                    }
                }
            }
            if (!update || offset == 0) {
                continue;
            }

            for (size_t i = 2; i < CONNECTIONS; ++i) {
                if (poll_descriptors[i].fd != -1) {
                    poll_descriptors[i].events = POLLOUT;
                }
            }


            std::string ui_string = "\e[1;1H\e[2J";
            ui_string += "------------------------------------------------------------------------\n\n";
            ui_string += " SIK Radio\n\n";
            ui_string += "------------------------------------------------------------------------\n\n";

            {
                std::lock_guard<std::mutex> lock{change_station_mut};
                std::vector<Station_Data> stations_vec;
                size_t curr_index = 0;
                bool stop = false;
                for (auto const &[key, value]: stations) {
                    stations_vec.push_back(key);
                    if (key.name == curr_station.name &&
                        key.port == curr_station.port &&
                        key.ip_mreq.imr_multiaddr.s_addr ==
                        curr_station.ip_mreq.imr_multiaddr.s_addr) {
                        stop = true;
                    }
                    if (!stop) {
                        ++curr_index;
                    }
                }
                if (curr_station.name.empty()) {
                    if (activated && !stations_vec.empty()) {
                        new_station(stations_vec[0]);
                    }
                } else {
                    size_t size = stations_vec.size();

                    Station_Data new_selected =
                            stations_vec[
                                    ((static_cast<ssize_t>(curr_index) + offset)
                                     % size + size) % size];

                    if (offset % size != 0) {
                        new_station(new_selected);
                    }
                }

                for (auto const &station: stations_vec) {
                    if (curr_station.name == station.name &&
                        curr_station.port == station.port &&
                        curr_station.ip_mreq.imr_multiaddr.s_addr ==
                        station.ip_mreq.imr_multiaddr.s_addr) {
                        ui_string += " > ";
                    }
                    ui_string += station.name;
                    ui_string += "\n\n";
                }
            }
            for (size_t i = 2; i < CONNECTIONS; ++i) {
                if (poll_descriptors[i].fd != -1 && (poll_descriptors[i].revents & POLLOUT)) {
                    if (update || offset != 0) {
                        first_time[i] = false;
                        ssize_t sent_bytes = write(poll_descriptors[i].fd, ui_string.c_str(), ui_string.length());
                        if (sent_bytes < 0) { // zamknij w przypadku błędu zapisu
                            if (close(poll_descriptors[i].fd) < 0) {
                                throw std::runtime_error("Error closing socket");
                            }
                            poll_descriptors[i].fd = -1;
                            active_clients -= 1;
                        }
                    }
                    if (first_time[i]) {
                        first_time[i] = false;
                        // TODO disable buffer
                        ssize_t sent_bytes = write(poll_descriptors[i].fd, ui_string.c_str(), ui_string.length());
                        if (sent_bytes < 0) { // zamknij w przypadku błędu zapisu
                            if (close(poll_descriptors[i].fd) < 0) {
                                throw std::runtime_error("Error closing socket");
                            }
                            poll_descriptors[i].fd = -1;
                            active_clients -= 1;
                        }
                    }
                }
                if (poll_descriptors[i].fd != -1) {
                    poll_descriptors[i].events = POLLIN;
                }
            }
        }
    }
}

[[noreturn]] void Receiver::run() {
    if (pipe(pipe_dsc) < 0) {
        throw std::runtime_error("pipe() failed");
    }
    std::jthread lookuper{&Receiver::lookuper_wrap, this};
    std::jthread listener{&Receiver::listener_wrap, this};
    std::jthread data_receiver{&Receiver::data_receiver_wrap, this};
    std::jthread writer{&Receiver::writer_wrap, this};
    try {
        gui_handler();
    } catch (std::exception &e) {
        main_exception = true;
        {
            std::lock_guard<std::mutex> lock{mut};
            writing = true;
            loop_start = true;
            receiving = true;
            next_to_print = 0;
        }
        cv_writing.notify_one();
        cv_receiving.notify_one();
        cv_loop_start.notify_one();
        throw;
    }
}

void Receiver::handle_main_exception() {
    if (main_exception) {
        throw std::runtime_error("Main exception");
    }
}

[[noreturn]] void Receiver::lookuper() {
    while (true) {
        handle_main_exception();
        uint64_t time = time_since_epoch_ms();

        std::string msg = "ZERO_SEVEN_COME_IN\n";
        ssize_t sent_bytes = sendto(lookup_socket_fd, msg.c_str(), msg.length(),
                                    0, (struct sockaddr*) &discover_address,
                                    sizeof(discover_address));
        if (sent_bytes < 0) {
            continue;
        }

        bool receiving_curr_value;
        Station_Data curr_station_curr_value;
        {
            std::lock_guard<std::mutex> lock{mut};
            handle_main_exception();
            receiving_curr_value = receiving;
        }
        {
            std::lock_guard<std::mutex> lock{change_station_mut};
            bool set_new = receiving_curr_value && !stations.empty() &&
                    stations[curr_station] + STATION_TIMEOUT < time;

            bool update = std::erase_if(stations, [time](const auto& item) {
                auto const& [key, value] = item;
                return value + STATION_TIMEOUT < time;
            }) > 0;

            if (receiving_curr_value && stations.empty()) {
                Station_Data empty_station;
                empty_station.name = "";
                new_station(empty_station);
            } else if (set_new) {
                Station_Data new_stat = stations.begin()->first;
                for (auto const &[key, value]: stations) {
                    if (key.name == favorite_name) {
                        new_stat = key;
                        break;
                    }
                }
                new_station(new_stat);
            }
            if (update) {
                ssize_t written_bytes = write(pipe_dsc[1], update_message.c_str(),
                                              update_message.length());
                if (written_bytes < 0 || (size_t) written_bytes < update_message.length()) {
                    throw std::runtime_error("Writing to pipe failed");
                }
            }
        }

        uint64_t time_diff = time_since_epoch_ms() - time;
        if (time_diff > LOOKUP_SLEEP) { // raczej nie powinno się wydarzyć
            continue;
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(
                LOOKUP_SLEEP - time_diff));
    }
}

void Receiver::lookuper_wrap() {
    try {
        lookuper();
    } catch (std::exception &e) {
        std::lock_guard<std::mutex> lock{mut};
        exception_to_throw = std::current_exception();
    }
}

[[noreturn]] void Receiver::listener() {
    while (true) {
        handle_main_exception();
        struct sockaddr_in received_address;
        socklen_t address_length = (socklen_t) sizeof(received_address);

        char reply_buf[REPLY_BUFSIZE];

        ssize_t read_bytes = recvfrom(reply_socket_fd,
                                           reply_buf, REPLY_BUFSIZE, 0,
                                           (struct sockaddr *)
                                                   &received_address,
                                                   &address_length);
        if (read_bytes < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                continue;
            }
            throw std::runtime_error("recvfrom() failed");
        }
        reply_buf[read_bytes] = '\0';

        if (std::regex_match(reply_buf, std::regex(R"(BOREWICZ_HERE [0-9\.]+ [0-9]+ [\x21-\x7F][\x20-\x7F]*[\x21-\x7F]\n)"))) {
            std::string reply(reply_buf);
            reply.erase(0, REPLY_HEADER_LEN);
            std::istringstream reply_stream(reply);
            std::string multicast_address;
            std::string port_string;
            std::string name;

            std::getline(reply_stream, multicast_address, ' ');
            std::getline(reply_stream, port_string, ' ');
            std::getline(reply_stream, name, ' ');
            name.pop_back();

            if (name.length() > 64) {
                continue;
            }

            unsigned long port = std::stoul(port_string);
            if (port > UINT16_MAX) {
                continue;
            }

            struct ip_mreq ip_mreq;
            ip_mreq.imr_interface.s_addr = htonl(INADDR_ANY);
            if (inet_aton(multicast_address.c_str(),
                          &ip_mreq.imr_multiaddr) == 0) {
                continue;
            }

            Station_Data station_data;
            station_data.name = name;
            station_data.ip_mreq = ip_mreq;
            station_data.port = port;
            station_data.address = received_address;
            station_data.address_length = address_length;

            std::lock_guard<std::mutex> lock{change_station_mut};
            bool update = false;
            if (name == favorite_name) {
                bool flag = true;
                for (auto const &[key, value]: stations) {
                    if (key.name == name) {
                        flag = false;
                    }
                }
                if (flag) {
                    new_station(station_data);
                    update = true;
                }
            }
            if (favorite_name.empty() && stations.empty()) {
                new_station(station_data);
                update = true;
            }
            stations[station_data] = time_since_epoch_ms();
            if (update) {
                ssize_t written_bytes = write(pipe_dsc[1], update_message.c_str(),
                                              update_message.length());
                if (written_bytes < 0 || (size_t) written_bytes < update_message.length()) {
                    throw std::runtime_error("Writing to pipe failed");
                }
            }
        }
    }
}

void Receiver::listener_wrap() {
    try {
        listener();
    } catch (std::exception &e) {
        std::lock_guard<std::mutex> lock{mut};
        exception_to_throw = std::current_exception();
    }
}

void Receiver::new_station(const Station_Data& station_data) {
    {
        std::unique_lock<std::mutex> lock(mut);
        handle_main_exception();
        bool old_receiving = receiving;
        receiving = false;
        cv_loop_start.wait(lock, [this] { return loop_start; });
        if (old_receiving) {
            if (setsockopt(data_socket_fd, IPPROTO_IP, IP_DROP_MEMBERSHIP,
                           (void *) &curr_station.ip_mreq,
                           sizeof(curr_station.ip_mreq)) < 0) {
                throw std::runtime_error("Error configuring socket");
            }
            if (close(data_socket_fd) < 0) {
                throw std::runtime_error("Error closing socket");
            }
        }
        curr_station = station_data;
        data_socket_fd = bind_socket(station_data.port, UDP, false);
        struct timeval timeout;
        timeout.tv_sec = 1; // TODO kurwa mać
        timeout.tv_usec = 0;
        if (setsockopt(data_socket_fd, SOL_SOCKET, SO_RCVTIMEO,
                       (const char *) &timeout, sizeof timeout) < 0) {
            throw std::runtime_error("Error configuring socket");
        }
        receiving = true;
    }
    cv_receiving.notify_one();
}

[[noreturn]] void Receiver::data_receiver() {
    while (true) {
        handle_main_exception();
        {
            std::lock_guard<std::mutex> lock{mut};
            loop_start = true;
        }
        cv_loop_start.notify_one();
        {
            std::unique_lock<std::mutex> lock(mut);
            cv_receiving.wait(lock, [this] { return receiving; });
        }
        if (setsockopt(data_socket_fd, IPPROTO_IP, IP_ADD_MEMBERSHIP,
                       (void *) &curr_station.ip_mreq,
                       sizeof curr_station.ip_mreq) < 0) {
            throw std::runtime_error("Error configuring socket");
        }

        session_id = 0;
        while (true) {
            handle_main_exception();
            int retval = receive_message();
            if (retval == -1) {
                break;
            }
            if (retval == 0) {
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
}

void Receiver::data_receiver_wrap() {
    try {
        data_receiver();
    } catch (std::exception &e) {
        std::lock_guard<std::mutex> lock{mut};
        exception_to_throw = std::current_exception();
    }
}

/**
 * Kod wątku wypisującego dane binarne na standardowe wyjście.
 */
[[noreturn]] void Receiver::writer() {

    while (true) {
        handle_main_exception();
        // czeka na możliwość pisania
        {
            std::unique_lock<std::mutex> lock(mut);
            cv_writing.wait(lock, [this] { return writing; });
        }
        while (true) {
            handle_main_exception();
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
                    if (std::fwrite(&buffer[next_to_print %
                                        max_packets * packet_size], 1,
                                packet_size, stdout) < packet_size) {
                        throw std::runtime_error("Error printing to stdout");
                    }
                    fflush(stdout);
                }
                ++next_to_print;
            }
        }
    }
}

void Receiver::writer_wrap() {
    try {
        writer();
    } catch (std::exception &e) {
        std::lock_guard<std::mutex> lock{mut};
        exception_to_throw = std::current_exception();
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
 * Zwraca 1, jeśli wiadomość została poprawnie odczytana (i zapisuje ją
 * w msg_buffer), 0, jeśli została porzucona, a -1, jeśli należy zakończyć
 * odbieranie.
 */
int Receiver::receive_message() {
    uint64_t new_session_id;

    struct sockaddr_in received_address;
    socklen_t address_length = (socklen_t) sizeof(received_address);

    ssize_t read_bytes = recvfrom(data_socket_fd, &new_session_id, 8,
                                       MSG_PEEK | MSG_TRUNC, (struct sockaddr *)
                                               &received_address, &address_length);
    {
        std::lock_guard<std::mutex> lock{mut};
        if (!receiving) {
            return -1;
        }
    }
    if (read_bytes < 0) {
        return 0;
    }

    new_session_id = be64toh(new_session_id);

    // porzucamy paczkę, jeśli przyszła ze złego adresu lub jest ze
    // starszej sesji (przesyłamy po UDP, więc nie musimy wczytywać
    // całej)
    if (received_address.sin_addr.s_addr != curr_station.address.sin_addr.s_addr
        || new_session_id < session_id) {
        recvfrom(data_socket_fd, &new_session_id, 8, 0, (struct sockaddr *)
                &received_address, &address_length);
        {
            std::lock_guard<std::mutex> lock{mut};
            if (!receiving) {
                return -1;
            }
        }

        return 0;
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
        recvfrom(data_socket_fd, msg_buffer, packet_size + 16, 0,
                      (struct sockaddr *) &received_address,
                      &address_length);
        {
            std::lock_guard<std::mutex> lock{mut};
            if (!receiving) {
                return -1;
            }
        }
        memcpy(&byte0, &msg_buffer[8], 8);
        byte0 = be64toh(byte0);
    } else {
        recvfrom(data_socket_fd, msg_buffer, packet_size + 16, 0,
                      (struct sockaddr *) &received_address,
                      &address_length);
        {
            std::lock_guard<std::mutex> lock{mut};
            if (!receiving) {
                return -1;
            }
        }
    }

    return 1;
}