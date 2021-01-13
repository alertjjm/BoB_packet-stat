#include <stdio.h>
#include <pcap.h>
#include <stdint.h>
#include <unordered_map>
#include<iostream>
#include <set>
#include "header.h"
#define ETH_SIZE 14
#define MIN(a, b) (((a) < (b)) ? (a) : (b))
#define TX 1
#define RX 0
using namespace std;
typedef struct pcktinfo{
    int tx_packets;
    int tx_bytes;
    int rx_packets;
    int rx_bytes;
}pcktinfo;

unordered_map<uint32_t, pcktinfo> iphashmap;
set<uint32_t> keys;
//packet.sniff_ip.in_addr.s_addr is uint32
void usage() {
    printf("syntax: pcap-stl <filename>\n");
    printf("sample: pcap-stl test.pcap\n");
}
void insert(uint32_t ipaddr, int bytes, int status){
    auto pos=iphashmap.find(ipaddr);
    if(pos==iphashmap.end()){
        pcktinfo newpcktinfo={0,};
        iphashmap[ipaddr]=newpcktinfo;
    }
    switch (status)
    {
    case TX:
        iphashmap[ipaddr].tx_packets++;
        iphashmap[ipaddr].tx_bytes+=bytes;
        break;
    
    case RX:
        iphashmap[ipaddr].rx_packets++;
        iphashmap[ipaddr].rx_bytes+=bytes;
        break;
    }
}
int readpackets(pcap_t* handle){
    struct pcap_pkthdr* header;
    const u_char* packet;
    u_int size_ip,size_tcp,size_payload; //size of the headers and payload
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == -2) return res;
    if (res == -1) {
        printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
        exit(1);
    }
    //initiailize components of packet
    struct sniff_ethernet* eth_header=(struct sniff_ethernet*)packet;
    struct sniff_ip* ip_header=(struct sniff_ip*)(packet+ETH_SIZE);
    size_ip = IP_HL(ip_header)*4;
    keys.insert(ip_header->ip_src.s_addr);
    keys.insert(ip_header->ip_dst.s_addr);
    insert(ip_header->ip_src.s_addr,header->caplen,TX);
    insert(ip_header->ip_dst.s_addr,header->caplen,RX);
    return res;
}
int main(int argc, char* argv[]) {
    if (argc != 2) {
        usage();
        return -1;
    }
    char* filename = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_offline(filename, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "pcap_open_offline(%s) return nullptr - %s\n", filename, errbuf);
        return -1;
    }
    while (readpackets(handle)>0);
    pcap_close(handle);
    for (auto iter = keys.begin(); iter != keys.end(); ++iter){
        pcktinfo temppcktinfo=iphashmap[*iter];
        in_addr tempip;
        tempip.s_addr=*iter;
        printf("IP: %s\tTX_packets: %d\tTX_bytes: %d\tRX_packets: %d\tRX_bytes: %d\n", inet_ntoa(tempip),temppcktinfo.tx_packets,temppcktinfo.tx_bytes,temppcktinfo.rx_packets,temppcktinfo.rx_bytes);
    }
}
