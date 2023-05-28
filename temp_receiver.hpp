#ifndef SIKRADIO_TEMP_RECEIVER_HPP
#define SIKRADIO_TEMP_RECEIVER_HPP

#include "receiver.hpp"

/**
 * Klasa zawierająca potrzebne dane do odbierania w formie podawanej na wejściu.
 * Służy jako obiekt pośredni między odczytem danych a właściwym odbiornikiem
 * (klasy Receiver), który ma już wszystkie dane w formie przetworzonej na
 * potrzeby nadawania.
 */
class Temp_Receiver {
public:
    Temp_Receiver(std::string _discover_address_string, uint16_t _ctrl_port,
                  uint16_t _ui_port, size_t _buffer_size, uint64_t _rexmit_time,
                  std::string _favorite_name);

    Receiver make_receiver();

private:
    const std::string discover_address_string;
    const uint16_t ctrl_port;
    const uint16_t ui_port;
    const size_t buffer_size;
    const uint64_t rexmit_time;
    const std::string favorite_name;
};


#endif //SIKRADIO_TEMP_RECEIVER_HPP
