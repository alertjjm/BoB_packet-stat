
all: packet-stat

packet-stat: header.o datastructure.o main.o
	g++ -o packet-stat header.o datastructure.o main.o -lpcap

header.o: header.h header.cpp
	g++ -c -o header.o header.cpp -lpcap

datastructure.o: datastructure.h datastructure.cpp
	g++ -c -o datastructure.o datastructure.cpp

main.o: main.cpp header.h
	g++ -c -o main.o main.cpp -lpcap

clean:
	rm -f packet-stat *.o
