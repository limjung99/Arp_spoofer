#include "pch.h"
#include "arpspoofer.h"


ArpSpoofer::ArpSpoofer(string interfacename){
    this->interfacename = interfacename;
    /*------------------------------------------------*/
    //나의 mac주소 구하기  
    string my_mac_addr;
    string my_ip_addr;
	string my_mac_filpath = "/sys/class/net/"+interfacename+"/address";
	ifstream ifs(my_mac_filpath);
	ifs>>my_mac_addr;
	for(int i=0;i<my_mac_addr.size();i++){
		my_mac_addr[i]=toupper(my_mac_addr[i]);
	}
    myMac = my_mac_addr;
	ifs.close();
    //나의 ip주소 구하기 
	struct ifaddrs* ifAddrList = nullptr;
    struct ifaddrs* ifa = nullptr;
	char ipAddress[INET6_ADDRSTRLEN];
    // getifaddrs() 함수를 사용하여 네트워크 인터페이스 목록을 가져오기 
    if (getifaddrs(&ifAddrList) == -1) {
        std::cerr << "Failed to get interface list" << std::endl;
        return;
    }
    // 인터페이스 목록을 순회하면서 IP 주소를 확인
    for (ifa = ifAddrList; ifa != nullptr; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == nullptr) {
            continue;
        }
        // 해당 인터페이스의 이름이 interfacename인 경우에만 처리 
        if (strcmp(ifa->ifa_name, interfacename.c_str()) == 0) {
            // AF_INET 
            if (ifa->ifa_addr->sa_family == AF_INET) {
                void* addrPtr;
                if (ifa->ifa_addr->sa_family == AF_INET) {
                    addrPtr = &((struct sockaddr_in*)ifa->ifa_addr)->sin_addr;
                }
                // IP 주소를 문자열로 변환합니다.
                inet_ntop(ifa->ifa_addr->sa_family, addrPtr, ipAddress, INET6_ADDRSTRLEN);
                my_ip_addr = ipAddress;
                break; // ens33 인터페이스 찾음 
            }
        }
    }
    //메모리 해제
    freeifaddrs(ifAddrList);
    /*----------------------------------------------------------------------*/
	my_ip_addr = ipAddress;
    myIp = my_ip_addr;
}

void ArpSpoofer::getMyIp(){

}

void ArpSpoofer::getMyMac(){

}