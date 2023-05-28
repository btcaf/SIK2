#include <iostream>
#include "receiver.hpp"
#include "temp_receiver.hpp"
#include "parse_receiver_args.hpp"

int main(int argc, char *argv[]) {
    try {
        Temp_Receiver temp_receiver = parse_receiver_args(argc, argv);
        Receiver receiver = temp_receiver.make_receiver();
        receiver.run();
    } catch (std::exception const &e) {
        std::cerr << e.what() << '\n';
        return 1;
    }

    return 0;
}