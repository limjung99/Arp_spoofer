#include "packetmanager.h"
#include "etharp.h"

PacketManager::PacketManager(string interfacename){
	char errbuf[PCAP_ERRBUF_SIZE];
	this->handle = pcap_open_live(interfacename.c_str(), 1024, 1, 1000, errbuf);
    if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", interfacename.c_str(), errbuf);
		return;
	}
}

/* type에 따른 arp 프로토콜을 통한 패킷 송신 함수 */
void PacketManager::sendArpPacket(string dmac,string smac,string sip,string tmac,string tip,u_int16_t type){
    EthArpPacket packet;
	packet.eth_.dmac_ = Mac(dmac);
	packet.eth_.smac_ = Mac(smac);
	packet.eth_.type_ = htons(EthHdr::Arp);
	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(type);
	packet.arp_.smac_ = Mac(smac);
	packet.arp_.sip_ = htonl(Ip(sip));
	packet.arp_.tmac_ = Mac(tmac);
	packet.arp_.tip_ = htonl(Ip(tip));
    //send ARP packet
	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}
}

pcap_t* PacketManager::getHandler(){return handle;}

void PacketManager::close(){pcap_close(handle);}

int PacketManager::packetCapture(const u_char*& packet,pcap_pkthdr*& header){
	int res = pcap_next_ex(handle, &header, &packet);
	return res;
}

int PacketManager::sendPacket(const u_char*& packet,pcap_pkthdr*& header){
	cout<<header->caplen<<endl;
	int res = pcap_sendpacket(handle,packet,header->caplen);
	return res;
}