#include "pch.h"
#include "ip.h"
#include "mac.h"

class PacketManager{
    pcap_t *handle; /* packetmanager의 패킷 핸들러 멤버 포인터변수 */
    public:
        PacketManager(string interfacename);
        void sendArpPacket(string dmac,string smac,string sip,string tmac,string tip,u_int16_t type); /* type에 따른 Arp프로토콜 패킷을 전송하는 함수 */
        pcap_t* getHandler();
        void close();
        int packetCapture(const u_char*& packet,pcap_pkthdr*& header);
        int sendPacket(const u_char*& packet,pcap_pkthdr*& header);
};