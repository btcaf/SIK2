#ifndef SIKRADIO_TEMP_SENDER_HPP
#define SIKRADIO_TEMP_SENDER_HPP

#include "sender.hpp"

/**
 * Klasa zawierająca potrzebne dane do nadawania w formie podawanej na wejściu.
 * Służy jako obiekt pośredni między odczytem danych a właściwym nadajnikiem
 * (klasy Sender), który ma już wszystkie dane w formie przetworzonej na
 * potrzeby nadawania.
 */
class Temp_Sender {
public:
    Temp_Sender(uint64_t _data_port, size_t _packet_size, std::string _name,
                std::string _multicast_address_string, uint16_t ctrl_port,
                size_t queue_size, uint64_t rexmit_time);

    Sender make_sender();

private:
    const uint16_t data_port;
    const size_t packet_size;
    const std::string name;
    const std::string multicast_address_string;
    const uint16_t ctrl_port;
    const size_t queue_size;
    const uint64_t rexmit_time;
};

#endif //SIKRADIO_TEMP_SENDER_HPP
