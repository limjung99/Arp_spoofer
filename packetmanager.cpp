#include "packetmanager.h"
#include "etharp.h"

/* PacketListner */
PacketListner* PacketListner::getInstance(){
	if(instance==nullptr){
		instance = new PacketListner();
		return instance;
	}
	return instance;
}

void PacketListner::initState(char* dev){
	char errbuf[PCAP_ERRBUF_SIZE];
	this->handle = pcap_open_live(dev, 1024, 1, 1000, errbuf);
    if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return;
	}
}

int PacketListner::capturePacket(const u_char*& packet,pcap_pkthdr*& header){
	int res = pcap_next_ex(handle, &header, &packet);
	return res;
}





/* PacketSender */
PacketSender* PacketSender::getInstance(){
	if(instance==nullptr){
		instance = new PacketSender();
		return instance;
	}
	return instance;
}

void PacketSender::initState(char* dev){
	char errbuf[PCAP_ERRBUF_SIZE];
	this->handle = pcap_open_live(dev, 1024, 1, 1000, errbuf);
    if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return;
	}
}

void PacketSender::sendArpPacket(Mac dmac,Mac smac,Ip sip,Mac tmac,Ip tip,u_int16_t type){
	EthArpPacket packet;
	packet.eth_.dmac_ = dmac;
	packet.eth_.smac_ = smac;
	packet.eth_.type_ = htons(EthHdr::Arp);
	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;	
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(type);
	packet.arp_.smac_ = smac;
	packet.arp_.sip_ = htonl(sip);
	packet.arp_.tmac_ = tmac;
	packet.arp_.tip_ = htonl(tip);
    //send ARP packet
	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}
}

