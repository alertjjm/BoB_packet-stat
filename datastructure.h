#pragma once
#include <stdlib.h>
#include<string>
#include <arpa/inet.h>
#include <unordered_map>
#include<iostream>
#define TX 1
#define RX 0
using namespace std;
typedef struct pcktinfo{
    int tx_packets;
    int tx_bytes;
    int rx_packets;
    int rx_bytes;
}pcktinfo;
typedef struct tcpudpkey{
    uint32_t ipaddr;
    u_short portnum;
    bool operator == (const tcpudpkey& r) const { return (ipaddr == r.ipaddr) && (portnum==r.portnum); }
    bool operator < (const tcpudpkey& r) const { return (ipaddr < r.ipaddr) || ((ipaddr == r.ipaddr)&&(portnum<r.portnum)); }
    bool operator > (const tcpudpkey& r) const { return r<(*this); }
}tcpudpkey;
typedef struct composipkey{
    uint32_t ipaddrA;
    uint32_t ipaddrB;
    bool operator == (const composipkey& r) const { return (ipaddrA == r.ipaddrA) && (ipaddrB==r.ipaddrB); }
    bool operator < (const composipkey& r) const { return (ipaddrA < r.ipaddrA) || ((ipaddrA == r.ipaddrA)&&(ipaddrB<r.ipaddrB)); }
}composipkey;
typedef struct composethkey{
    string macA;
    string macB;
    bool operator == (const composethkey& r) const { return (macA == r.macA) && (macB==r.macB); }
    bool operator < (const composethkey& r) const { return (macA < r.macA) || ((macA == r.macA)&&(macB<r.macB)); }
}composmackey;
typedef struct composetcpudpkey{
    tcpudpkey keyA;
    tcpudpkey keyB;
    bool operator == (const composetcpudpkey& r) const { return (keyA == r.keyA) && (keyB==r.keyB); }
    bool operator < (const composetcpudpkey& r) const { return (keyA < r.keyA) || ((keyA == r.keyA)&&(keyB<r.keyB)); }
}composetcpudpkey;

namespace std {
	template<>
	struct hash<tcpudpkey> {
		size_t operator() (const tcpudpkey & rhs) const {
			size_t h1 = std::hash<std::uint32_t>{}(rhs.ipaddr);
            size_t h2 = std::hash<u_short>{}(rhs.portnum);
            return h1 ^ (h2 << 1);
		}
	};
}
namespace std {
	template<>
	struct hash<composipkey> {
		size_t operator() (const composipkey & rhs) const {
			size_t h1 = std::hash<std::uint32_t>{}(rhs.ipaddrA);
            size_t h2 = std::hash<std::uint32_t>{}(rhs.ipaddrB);
            return h1 ^ (h2 << 1);
		}
	};
}
namespace std {
	template<>
	struct hash<composethkey> {
		size_t operator() (const composethkey & rhs) const {
			size_t h1 = std::hash<string>{}(rhs.macA);
            size_t h2 = std::hash<string>{}(rhs.macB);
            return h1 ^ (h2 << 1);
		}
	};
}
namespace std {
	template<>
	struct hash<composetcpudpkey> {
		size_t operator() (const composetcpudpkey & rhs) const {
			size_t h1 = std::hash<tcpudpkey>{}(rhs.keyA);
            size_t h2 = std::hash<tcpudpkey>{}(rhs.keyB);
            return h1 ^ (h2 << 1);
		}
	};
}

    
        