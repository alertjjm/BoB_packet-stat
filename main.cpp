#include <stdio.h>
#include <pcap.h>
#include <stdint.h>
#include <unordered_map>
#include<iostream>
#include<string>
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
unordered_map<string, pcktinfo> ethhashmap;

set<uint32_t> ipkeys;
set<string> ethkeys;
//packet.sniff_ip.in_addr.s_addr is uint32
void usage() {
    printf("syntax: pcap-stl <filename>\n");
    printf("sample: pcap-stl test.pcap\n");
}
void ipinsert(uint32_t ipaddr, int bytes, int status){
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
void ethinsert(string macaddr, int bytes, int status){
    auto pos=ethhashmap.find(macaddr);
    if(pos==ethhashmap.end()){
        pcktinfo newpcktinfo={0,};
        ethhashmap[macaddr]=newpcktinfo;
    }
    switch (status)
    {
    case TX:
        ethhashmap[macaddr].tx_packets++;
        ethhashmap[macaddr].tx_bytes+=bytes;
        break;
    
    case RX:
        ethhashmap[macaddr].rx_packets++;
        ethhashmap[macaddr].rx_bytes+=bytes;
        break;
    }
}
string mactostring(u_char macaddr[ETHER_ADDR_LEN]){
	char buf[32]; // enough size
	sprintf(buf, "%02x:%02x:%02x:%02x:%02x:%02x",
		macaddr[0],
		macaddr[1],
		macaddr[2],
		macaddr[3],
		macaddr[4],
		macaddr[5]);
	return string(buf);
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
    //ethernet area
    struct sniff_ethernet* eth_header=(struct sniff_ethernet*)packet;
    string srcmac=mactostring(eth_header->ether_shost); string dstmac=mactostring(eth_header->ether_dhost);
    ethkeys.insert(srcmac); ethkeys.insert(dstmac);
    ethinsert(srcmac,header->caplen,TX); ethinsert(dstmac,header->caplen,RX);
    //ip area
    struct sniff_ip* ip_header=(struct sniff_ip*)(packet+ETH_SIZE);
    size_ip = IP_HL(ip_header)*4;
    ipkeys.insert(ip_header->ip_src.s_addr); ipkeys.insert(ip_header->ip_dst.s_addr);
    ipinsert(ip_header->ip_src.s_addr,header->caplen,TX); ipinsert(ip_header->ip_dst.s_addr,header->caplen,RX);
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
    cout<<"--------------------------------------[ETHERNET]--------------------------------------"<<endl;
    for (auto iter = ethkeys.begin(); iter != ethkeys.end(); ++iter){
        pcktinfo temppcktinfo=ethhashmap[*iter];
        string tempmac;
        tempmac=*iter;
        cout<<"MAC: "<<tempmac<<"\tTX_packets: "<<temppcktinfo.tx_packets<<"\tTX_bytes: "<<temppcktinfo.tx_bytes<<"\tRX_packets: "<<temppcktinfo.rx_packets<<"\tRX_bytes: "<<temppcktinfo.rx_bytes<<endl;
    }
    cout<<endl;
    cout<<"----------------------------------------[IP]----------------------------------------"<<endl;
    for (auto iter = ipkeys.begin(); iter != ipkeys.end(); ++iter){
        pcktinfo temppcktinfo=iphashmap[*iter];
        in_addr tempip;
        tempip.s_addr=*iter;
        printf("IP: %s\tTX_packets: %d\tTX_bytes: %d\tRX_packets: %d\tRX_bytes: %d\n", inet_ntoa(tempip),temppcktinfo.tx_packets,temppcktinfo.tx_bytes,temppcktinfo.rx_packets,temppcktinfo.rx_bytes);
    }
}
