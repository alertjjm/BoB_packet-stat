
all: pcap-stl

pcap-stl: header.o main.o
	g++ -o pcap-stl header.o main.o -lpcap

header.o: header.h header.cpp
	g++ -c -o header.o header.cpp -lpcap

main.o: main.cpp header.h
	g++ -c -o main.o main.cpp -lpcap

clean:
	rm -f pcap-stl *.o
