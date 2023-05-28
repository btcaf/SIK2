#include <iostream>
#include "sender.hpp"
#include "temp_sender.hpp"
#include "parse_sender_args.hpp"

int main(int argc, char *argv[]) {
    try {
        Temp_Sender temp_sender = parse_sender_args(argc, argv);
        Sender sender = temp_sender.make_sender();
        sender.run();
    } catch (std::exception const &e) {
        std::cerr << e.what() << '\n';
        return 1;
    }

    return 0;
}