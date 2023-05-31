#ifndef SIKRADIO_RECEIVER_HPP
#define SIKRADIO_RECEIVER_HPP

#include <cstdint>
#include <cstddef>
#include <netinet/in.h>
#include <mutex>
#include <condition_variable>
#include <unordered_set>
#include <map>
#include <vector>

using byte_t = uint8_t;

typedef struct station_data {
    std::string name;
    struct ip_mreq ip_mreq;
    uint16_t port;
    struct sockaddr_in address;
    socklen_t address_length;
} Station_Data;

struct station_data_cmp {
    bool operator()(const station_data& a, const station_data &b) const {
        if (a.name != b.name) {
            return a.name < b.name;
        }

        if (a.ip_mreq.imr_multiaddr.s_addr != b.ip_mreq.imr_multiaddr.s_addr) {
            return a.ip_mreq.imr_multiaddr.s_addr < b.ip_mreq.imr_multiaddr.s_addr;
        }

        return a.port < b.port;
    }
};

class Receiver {
public:
    Receiver(struct sockaddr_in _discover_address, int _lookup_socket_fd, int _ui_socket_fd,
            size_t _buffer_size, uint64_t _rexmit_time, int _rexmit_socket_fd, uint16_t _ctrl_port, std::string _favorite_name);

    ~Receiver();

    [[noreturn]] void run();

private:

    [[noreturn]] void gui_handler();

    void handle_main_exception();

    /**
     * Kod wątku wysyłającego komunikaty LOOKUP.
     */
    [[noreturn]] void lookuper();

    /**
     * Kod wątku odbierającego komunikaty REPLY.
     */
    [[noreturn]] void listener();

    void new_station(const Station_Data& station_data);

    /**
     * Kod wątku odbierającego dane binarne.
     */
    [[noreturn]] void data_receiver();

    /**
     * Kod wątku wypisującego dane binarne na standardowe wyjście.
     */
    [[noreturn]] void writer();

    /**
     * Kod wątku wysyłającego komunikaty REXMIT.
     */
    [[noreturn]] void rexmit_request_sender();

    void lookuper_wrap();
    void listener_wrap();
    void data_receiver_wrap();
    void writer_wrap();
    void rexmit_request_sender_wrap();

    void update_rexmit_request(uint64_t curr_packet);

    std::vector<std::string> create_rexmit_messages();

    /**
     * Usuwa informacje o tych odebranych paczkach, które zostały usunięte
     * z bufora (możliwe, że nie zostały jeszcze nadpisane, ale ich miejsce
     * jest zarezerwowane dla kolejnych paczek).
     */
    void clear_old_packets();

    /**
     * Zwraca 1, jeśli wiadomość została poprawnie odczytana (i zapisuje ją
     * w msg_buffer), 0, jeśli została porzucona, a -1, jeśli należy zakończyć
     * odbieranie.
     */
    int receive_message();

    static const uint64_t LOOKUP_SLEEP = 5000;
    static const uint64_t STATION_TIMEOUT = 20000;
    static const size_t REPLY_BUFSIZE = 100;
    static const size_t REPLY_HEADER_LEN = 14;
    static const size_t CONNECTIONS = 10;
    static const size_t QUEUE_LENGTH = 5;
    static const uint64_t TIMEOUT = 5000;
    static const size_t MAX_REXMIT_COUNT = 10;
    const std::string REXMIT_HEADER = "LOUDER_PLEASE ";

    std::atomic<bool> main_exception = false;
    std::exception_ptr exception_to_throw = nullptr;

    /* wyszukiwanie stacji */
    const struct sockaddr_in discover_address;
    int lookup_socket_fd;

    /* atrybuty związane z obsługą UI */
    int ui_socket_fd;
    int pipe_dsc[2];
    const std::string update_message = "UPDATE";

    std::map<Station_Data, uint64_t, station_data_cmp> stations;

    int data_socket_fd;
    Station_Data curr_station;
    bool receiving = false;
    bool loop_start = true;
    // numer sesji musi być dodatni, więc pierwsza paczka zostanie poprawnie
    // zidentyfikowana jako pochodząca z nowej sesji
    uint64_t session_id = 0;
    size_t packet_size = 0;
    uint64_t byte0 = 0;
    const size_t buffer_size;
    // zwalniany w destruktorze
    byte_t *buffer = new byte_t[buffer_size];
    byte_t *msg_buffer = NULL;
    uint64_t max_packets;

    std::mutex change_station_mut;
    std::mutex rexmit_requests_mut;
    std::mutex mut;
    std::condition_variable cv_writing;
    std::condition_variable cv_receiving;
    std::condition_variable cv_loop_start;
    bool writing = false;

    // numery paczek poniżej rozumiemy jako kolejne liczby całkowite,
    // licząc od 0 (czyli (first_byte_num - BYTE0) / PSIZE)

    // next_to_receive to numer następnej oczekiwanej paczki, oczywiście możemy
    // otrzymać najpierw inną
    uint64_t next_to_receive = 0;
    uint64_t next_to_print = 0;
    // przechowujemy numery tych odebranych, które jeszcze są przechowywane w
    // buforze
    std::unordered_set<uint64_t> received_packets;

    /* retransmisje */
    const uint64_t rexmit_time;
    int rexmit_socket_fd;
    std::unordered_set<uint64_t> rexmit_requests;
    const uint16_t ctrl_port;

    const std::string favorite_name;
};


#endif //SIKRADIO_RECEIVER_HPP
