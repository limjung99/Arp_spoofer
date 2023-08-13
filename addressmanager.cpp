#include "pch.h"
#include "addressmanager.h"


AddressManager* AddressManager::getInstacne(){
    if(instance==nullptr){
        instance = new AddressManager();
        return instance;
    }
    return instance;
}
    
void AddressManager::initState(char* dev){
    string my_mac_addr;
    string my_ip_addr;
    //나의 mac주소 구하기  
	string interface(dev);
	string my_mac_filpath = "/sys/class/net/"+interface+"/address";
	ifstream ifs(my_mac_filpath);
	ifs>>my_mac_addr;
	for(int i=0;i<my_mac_addr.size();i++){
		my_mac_addr[i]=toupper(my_mac_addr[i]);
	}
	ifs.close();
	//나의 ip주소 구하기 --> 이건 chatGPT 도움을 좀 받았습니다.
	struct ifaddrs* ifAddrList = nullptr;
    struct ifaddrs* ifa = nullptr;
	char ipAddress[INET6_ADDRSTRLEN];
    // getifaddrs() 함수를 사용하여 네트워크 인터페이스 목록을 가져옵니다.
    if (getifaddrs(&ifAddrList) == -1) {
        std::cerr << "Failed to get interface list" << std::endl;
        return;
    }
    // 인터페이스 목록을 순회하면서 IP 주소를 확인합니다.
    for (ifa = ifAddrList; ifa != nullptr; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == nullptr) {
            continue;
        }
        // 해당 인터페이스의 이름이 "ens33"인 경우에만 처리
        if (strcmp(ifa->ifa_name, dev) == 0) {
            // AF_INET 또는 AF_INET6 주소만 고려합니다.
            if (ifa->ifa_addr->sa_family == AF_INET || ifa->ifa_addr->sa_family == AF_INET6) {
                void* addrPtr;
                if (ifa->ifa_addr->sa_family == AF_INET) {
                    addrPtr = &((struct sockaddr_in*)ifa->ifa_addr)->sin_addr;
                } else {
                    addrPtr = &((struct sockaddr_in6*)ifa->ifa_addr)->sin6_addr;
                }
                // IP 주소를 문자열로 변환합니다.
                inet_ntop(ifa->ifa_addr->sa_family, addrPtr, ipAddress, INET6_ADDRSTRLEN);
                my_ip_addr = ipAddress;
                break; // ens33 인터페이스를 찾았으므로 루프를 빠져나갑니다.
            }
        }
    }
    //메모리 해제
    freeifaddrs(ifAddrList);
    myMac = Mac(my_mac_addr);
    myIp = Ip(my_ip_addr);
}