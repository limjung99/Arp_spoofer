#include "pch.h"
#include "ethhdr.h"
#include "mac.h"
#include "ip.h"
#include "arphdr.h"
#include "packetmanager.h"
#include "addressmanager.h"


// 입력받은 sender ip와 target ip 페어를 u_int32_t로 저장해야겠다 안그러면, 나중에 형변환이 까다로움 

void usage() {
	printf("syntax: arp_spoofer.out <interface> {sender_ip , target_ip } ...\n");
	printf("sample: send-arp-test wlan0 1.1.1.2 1.1.1.1\n");
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

	/* arp request 프로토콜로 Ip들의 Mac 주소를 질의 */
    for(int i=0;i<addrmanager.getCounter();i++){
		pair<Ip,Ip> ipPair = addrmanager.getIpPair(i);
		Ip sender = ipPair.first;
		Ip target = ipPair.second;
		/* sender mac 주소 질의 */
		packetmanager.sendArpPacket("FF:FF:FF:FF:FF:FF",string(addrmanager.getMyMac()),string(addrmanager.getMyIp()),"00:00:00:00:00:00",string(sender),2);



		/* target mac 주소 질의 */
		packetmanager.sendArpPacket("FF:FF:FF:FF:FF:FF",string(addrmanager.getMyMac()),string(addrmanager.getMyIp()),"00:00:00:00:00:00",string(target),2);
	}

	/* arp cache table 감염 */
	for(int i=0;i<addrmanager.getCounter();i++){
		pair<Ip,Ip> ipPair = addrmanager.getIpPair(i);
		Ip sender = ipPair.first;
		Ip target = ipPair.second;
	}
	
	//relay packets 과 infection이 풀림을 감지 -> multi thread로 병렬 처리
	

	/* 연결 종료 */
	packetmanager.close();
    return 0;
}
