#include "pch.h"
#include "ip.h"
#include "mac.h"
/* 각자 다른 세션 형성 */

class PacketListner{
    
    private:
        pcap_t* handle;
        static PacketListner* instance;
        PacketListner();
    public:
        static PacketListner* getInstance();
        void initState(char* dev);
        int capturePacket(const u_char*& packet,pcap_pkthdr*& pkthdr);
};

class PacketSender{
    private:
        pcap_t* handle;
        static PacketSender* instance;
        PacketSender();
    public:
        static PacketSender* getInstance();
        void initState(char* dev);
        void sendArpPacket(Mac dmac,Mac smac,Ip sip,Mac tmac,Ip tip,u_int16_t type);
};