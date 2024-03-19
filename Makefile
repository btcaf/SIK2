CXX = g++
CXXFLAGS = -Wall -O2 -std=c++20

.PHONY: all clean

all: sikradio-sender sikradio-receiver

common.o: common.cpp common.hpp
	${CXX} ${CXXFLAGS} -c $<

sender.o: sender.cpp sender.hpp blocking_queue.hpp
	${CXX} ${CXXFLAGS} -c $<

receiver.o: receiver.cpp receiver.hpp common.hpp
	${CXX} ${CXXFLAGS} -c $<

temp_sender.o: temp_sender.cpp temp_sender.hpp sender.hpp common.hpp
	${CXX} ${CXXFLAGS} -c $<

temp_receiver.o: temp_receiver.cpp temp_receiver.hpp receiver.hpp common.hpp
	${CXX} ${CXXFLAGS} -c $<

parse_sender_args.o: parse_sender_args.cpp parse_sender_args.hpp temp_sender.hpp
	${CXX} ${CXXFLAGS} -c $<

parse_receiver_args.o: parse_receiver_args.cpp parse_receiver_args.hpp temp_receiver.hpp
	${CXX} ${CXXFLAGS} -c $<

sikradio-sender-main.o: sikradio-sender-main.cpp sender.hpp temp_sender.hpp parse_sender_args.hpp
	${CXX} ${CXXFLAGS} -c $<

sikradio-receiver-main.o: sikradio-receiver-main.cpp receiver.hpp temp_receiver.hpp parse_receiver_args.hpp
	${CXX} ${CXXFLAGS} -c $<

sikradio-sender: sikradio-sender-main.o parse_sender_args.o temp_sender.o sender.o common.o
	${CXX} ${CXXFLAGS} -o sikradio-sender $^ -pthread -lboost_program_options

sikradio-receiver: sikradio-receiver-main.o parse_receiver_args.o temp_receiver.o receiver.o common.o
	${CXX} ${CXXFLAGS} -o sikradio-receiver $^ -pthread -lboost_program_options
	
clean:
	rm -f *.o sikradio-sender sikradio-receiver