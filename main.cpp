#include <stdio.h>
#include <pcap.h>
#include <stdint.h>
#include <unordered_map>
#include<iostream>
#include<string>
#include <set>
#include "header.h"
#include "datastructure.h"
#define ETH_SIZE 14
#define MIN(a, b) (((a) < (b)) ? (a) : (b))
#define MAX(a, b) (((a) > (b)) ? (a) : (b))


using namespace std;
unordered_map<uint32_t, pcktinfo> iphashmap;
unordered_map<string, pcktinfo> ethhashmap;
unordered_map<tcpudpkey, pcktinfo> tcphashmap;
unordered_map<tcpudpkey, pcktinfo> udphashmap;

set<uint32_t> ipkeys;
set<string> ethkeys;
set<tcpudpkey> tcpkeys;
set<tcpudpkey> udpkeys;
//conversation
unordered_map<composipkey, pcktinfo> conviphashmap;
unordered_map<composethkey, pcktinfo> convethhashmap;
unordered_map<composetcpudpkey, pcktinfo> convtcphashmap;
unordered_map<composetcpudpkey, pcktinfo> convudphashmap;

set<composipkey> convipkeys;
set<composethkey> convethkeys;
set<composetcpudpkey> convtcpkeys;
set<composetcpudpkey> convudpkeys;

//packet.sniff_ip.in_addr.s_addr is uint32
void usage() {
    printf("syntax: packet-stat <filename>\n");
    printf("sample: packet-stat test.pcap\n");
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
void tcpinsert(tcpudpkey key, int bytes, int status){
    auto pos=tcphashmap.find(key);
    if(pos==tcphashmap.end()){
        pcktinfo newpcktinfo={0,};
        tcphashmap[key]=newpcktinfo;
    }
    switch (status)
    {
    case TX:
        tcphashmap[key].tx_packets++;
        tcphashmap[key].tx_bytes+=bytes;
        break;
    
    case RX:
        tcphashmap[key].rx_packets++;
        tcphashmap[key].rx_bytes+=bytes;
        break;
    }
}
void udpinsert(tcpudpkey key, int bytes, int status){
    auto pos=udphashmap.find(key);
    if(pos==udphashmap.end()){
        pcktinfo newpcktinfo={0,};
        udphashmap[key]=newpcktinfo;
    }
    switch (status)
    {
    case TX:
        udphashmap[key].tx_packets++;
        udphashmap[key].tx_bytes+=bytes;
        break;
    
    case RX:
        udphashmap[key].rx_packets++;
        udphashmap[key].rx_bytes+=bytes;
        break;
    }
}
void convipinsert(composipkey key, int bytes, int status){
    auto pos=conviphashmap.find(key);
    if(pos==conviphashmap.end()){
        pcktinfo newpcktinfo={0,};
        conviphashmap[key]=newpcktinfo;
    }
    switch (status)
    {
    case TX:
        conviphashmap[key].tx_packets++;
        conviphashmap[key].tx_bytes+=bytes;
        break;
    
    case RX:
        conviphashmap[key].rx_packets++;
        conviphashmap[key].rx_bytes+=bytes;
        break;
    }
}
void convethinsert(composethkey key, int bytes, int status){
    auto pos=convethhashmap.find(key);
    if(pos==convethhashmap.end()){
        pcktinfo newpcktinfo={0,};
        convethhashmap[key]=newpcktinfo;
    }
    switch (status)
    {
    case TX:
        convethhashmap[key].tx_packets++;
        convethhashmap[key].tx_bytes+=bytes;
        break;
    
    case RX:
        convethhashmap[key].rx_packets++;
        convethhashmap[key].rx_bytes+=bytes;
        break;
    }
}
void convtcpinsert(composetcpudpkey key, int bytes, int status){
    auto pos=convtcphashmap.find(key);
    if(pos==convtcphashmap.end()){
        pcktinfo newpcktinfo={0,};
        convtcphashmap[key]=newpcktinfo;
    }
    switch (status)
    {
    case TX:
        convtcphashmap[key].tx_packets++;
        convtcphashmap[key].tx_bytes+=bytes;
        break;
    
    case RX:
        convtcphashmap[key].rx_packets++;
        convtcphashmap[key].rx_bytes+=bytes;
        break;
    }
}
void convudpinsert(composetcpudpkey key, int bytes, int status){
    auto pos=convudphashmap.find(key);
    if(pos==convudphashmap.end()){
        pcktinfo newpcktinfo={0,};
        convudphashmap[key]=newpcktinfo;
    }
    switch (status)
    {
    case TX:
        convudphashmap[key].tx_packets++;
        convudphashmap[key].tx_bytes+=bytes;
        break;
    
    case RX:
        convudphashmap[key].rx_packets++;
        convudphashmap[key].rx_bytes+=bytes;
        break;
    }
}
string mactostring(u_char macaddr[ETHER_ADDR_LEN]){
	char buf[32];
	sprintf(buf, "%02x:%02x:%02x:%02x:%02x:%02x", macaddr[0], macaddr[1], macaddr[2], macaddr[3], macaddr[4], macaddr[5]);
	return string(buf);
}
int readpackets(pcap_t* handle){
    int status;
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
    //conversation
    if(srcmac==MIN(srcmac,dstmac))
        status=TX;
    else status=RX;
    composethkey tempconvethkey={MIN(srcmac,dstmac),MAX(srcmac,dstmac)};
    convethkeys.insert(tempconvethkey);
    convethinsert(tempconvethkey,header->caplen,status);
    
    //ipv4 area
    if(ntohs(eth_header->ether_type)!=0x0800)
        return res;
    struct sniff_ip* ip_header=(struct sniff_ip*)(packet+ETH_SIZE);
    size_ip = IP_HL(ip_header)*4;
    ipkeys.insert(ip_header->ip_src.s_addr); ipkeys.insert(ip_header->ip_dst.s_addr);
    ipinsert(ip_header->ip_src.s_addr,header->caplen,TX); ipinsert(ip_header->ip_dst.s_addr,header->caplen,RX);
    //conversation
    if(ip_header->ip_src.s_addr==MIN(ip_header->ip_src.s_addr,ip_header->ip_dst.s_addr))
        status=TX;
    else status=RX;
    composipkey tempconvipkey={MIN(ip_header->ip_src.s_addr,ip_header->ip_dst.s_addr),MAX(ip_header->ip_src.s_addr,ip_header->ip_dst.s_addr)};
    convipkeys.insert(tempconvipkey);
    convipinsert(tempconvipkey,header->caplen,status);
    
    //tcp area
    if(ip_header->ip_p==IPPROTO_TCP){ //if pckt is tcp
        const struct sniff_tcp* tcp_header=(struct sniff_tcp*)(packet+ETH_SIZE+size_ip);
        tcpudpkey srctcpkey={ip_header->ip_src.s_addr,ntohs(tcp_header->th_sport)};
        tcpudpkey dsttcpkey={ip_header->ip_dst.s_addr,ntohs(tcp_header->th_dport)};
        tcpkeys.insert(srctcpkey); tcpkeys.insert(dsttcpkey);
        tcpinsert(srctcpkey,header->caplen,TX);
        tcpinsert(dsttcpkey,header->caplen,RX);
        //conversation
        if(srctcpkey==MIN(srctcpkey,dsttcpkey))
            status=TX;
        else status=RX;
        composetcpudpkey tempconvtcpkey={MIN(srctcpkey,dsttcpkey),MAX(srctcpkey,dsttcpkey)};
        convtcpkeys.insert(tempconvtcpkey);
        convtcpinsert(tempconvtcpkey,header->caplen,status);
    }
    else if(ip_header->ip_p==IPPROTO_UDP){//if pckt is udp
        const struct sniff_udp* udp_header=(struct sniff_udp*)(packet+ETH_SIZE+size_ip);
        tcpudpkey srcudpkey={ip_header->ip_src.s_addr,ntohs(udp_header->th_sport)};
        tcpudpkey dstudpkey={ip_header->ip_dst.s_addr,ntohs(udp_header->th_dport)};
        udpkeys.insert(srcudpkey); udpkeys.insert(dstudpkey);
        udpinsert(srcudpkey,header->caplen,TX);
        udpinsert(dstudpkey,header->caplen,RX);
        //conversation
        if(srcudpkey==MIN(srcudpkey,dstudpkey))
            status=TX;
        else status=RX;
        composetcpudpkey tempconvudpkey={MIN(srcudpkey,dstudpkey),MAX(srcudpkey,dstudpkey)};
        convudpkeys.insert(tempconvudpkey);
        convudpinsert(tempconvudpkey,header->caplen,status);
    }
    else return res;
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
    cout<<endl;
    cout<<"----------------------------------------[TCP]----------------------------------------"<<endl;
    for (auto iter = tcpkeys.begin(); iter != tcpkeys.end(); ++iter){
        tcpudpkey tempkey=*iter;
        pcktinfo temppcktinfo=tcphashmap[tempkey];
        in_addr tempip;
        tempip.s_addr=(*iter).ipaddr;
        printf("IP: %s\tPort: %d\tTX_packets: %d\tTX_bytes: %d\tRX_packets: %d\tRX_bytes: %d\n", inet_ntoa(tempip),(*iter).portnum,temppcktinfo.tx_packets,temppcktinfo.tx_bytes,temppcktinfo.rx_packets,temppcktinfo.rx_bytes);
    }
    cout<<endl;
    cout<<"----------------------------------------[UDP]----------------------------------------"<<endl;
    for (auto iter = udpkeys.begin(); iter != udpkeys.end(); ++iter){
        tcpudpkey tempkey=*iter;
        pcktinfo temppcktinfo=udphashmap[tempkey];
        in_addr tempip;
        tempip.s_addr=(*iter).ipaddr;
        printf("IP: %s\tPort: %d\tTX_packets: %d\tTX_bytes: %d\tRX_packets: %d\tRX_bytes: %d\n", inet_ntoa(tempip),(*iter).portnum,temppcktinfo.tx_packets,temppcktinfo.tx_bytes,temppcktinfo.rx_packets,temppcktinfo.rx_bytes);
    }
    cout<<endl;
    cout<<endl;
    cout<<"-Conversation-"<<endl;
    cout<<"--------------------------------------[ETHERNET]--------------------------------------"<<endl;
    for (auto iter = convethkeys.begin(); iter != convethkeys.end(); ++iter){
        pcktinfo temppcktinfo=convethhashmap[*iter];
        composethkey tempkey;
        tempkey=*iter;
        cout<<"(AddressA): "<<tempkey.macA<<"\t(AddressB): "<<tempkey.macB<<"\t(Packets A->B): "<<temppcktinfo.tx_packets<<"\t(Bytes A->B): "<<temppcktinfo.tx_bytes<<"\t(Packets B->A): "<<temppcktinfo.rx_packets<<"\t(Bytes B->A): "<<temppcktinfo.rx_bytes<<endl;
    }
    cout<<endl;
    cout<<"----------------------------------------[IP]----------------------------------------"<<endl;
    for (auto iter = convipkeys.begin(); iter != convipkeys.end(); ++iter){
        pcktinfo temppcktinfo=conviphashmap[*iter];
        in_addr tempip;
        composipkey tempkey=*iter;
        in_addr ipaddrA;
        ipaddrA.s_addr=(*iter).ipaddrA;
        in_addr ipaddrB;
        ipaddrB.s_addr=(*iter).ipaddrB;
        cout<<"(AddressA): "<<inet_ntoa(ipaddrA)<<"\t(AddressB): "<<inet_ntoa(ipaddrB)<<"\t(Packets A->B): "<<temppcktinfo.tx_packets<<"\t(Bytes A->B): "<<temppcktinfo.tx_bytes<<"\t(Packets B->A): "<<temppcktinfo.rx_packets<<"\t(Bytes B->A): "<<temppcktinfo.rx_bytes<<endl;
    }
    cout<<endl;
    cout<<"----------------------------------------[TCP]----------------------------------------"<<endl;
    for (auto iter = convtcpkeys.begin(); iter != convtcpkeys.end(); ++iter){
        composetcpudpkey temptcpkey=*iter;
        pcktinfo temppcktinfo=convtcphashmap[temptcpkey];
        composetcpudpkey tempkey=*iter;
        in_addr ipaddrA;
        ipaddrA.s_addr=(*iter).keyA.ipaddr;
        in_addr ipaddrB;
        ipaddrB.s_addr=(*iter).keyB.ipaddr;
        cout<<"(AddressA): "<<inet_ntoa(ipaddrA)<<"\t(Port A): "<<(*iter).keyA.portnum<<"\t(AddressB): "<<inet_ntoa(ipaddrB)<<"\t(Port B): "<<(*iter).keyB.portnum<<"\t(Packets A->B): "<<temppcktinfo.tx_packets<<"\t(Bytes A->B): "<<temppcktinfo.tx_bytes<<"\t(Packets B->A): "<<temppcktinfo.rx_packets<<"\t(Bytes B->A): "<<temppcktinfo.rx_bytes<<endl;
    }
    cout<<endl;
    cout<<"----------------------------------------[UDP]----------------------------------------"<<endl;
    for (auto iter = convudpkeys.begin(); iter != convudpkeys.end(); ++iter){
        composetcpudpkey tempudpkey=*iter;
        pcktinfo temppcktinfo=convudphashmap[tempudpkey];
        composetcpudpkey tempkey=*iter;
        in_addr ipaddrA;
        ipaddrA.s_addr=(*iter).keyA.ipaddr;
        in_addr ipaddrB;
        ipaddrB.s_addr=(*iter).keyB.ipaddr;
        cout<<"(AddressA): "<<inet_ntoa(ipaddrA)<<"\t(Port A): "<<(*iter).keyA.portnum<<"\t(AddressB): "<<inet_ntoa(ipaddrB)<<"\t(Port B): "<<(*iter).keyB.portnum<<"\t(Packets A->B): "<<temppcktinfo.tx_packets<<"\t(Bytes A->B): "<<temppcktinfo.tx_bytes<<"\t(Packets B->A): "<<temppcktinfo.rx_packets<<"\t(Bytes B->A): "<<temppcktinfo.rx_bytes<<endl;
    }
}
