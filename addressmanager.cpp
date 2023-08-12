#include "pch.h"
#include "addressmanager.h"


AddressManager::AddressManager(string interfacename){
    this->interfacename = interfacename;
    string my_mac_addr;
    string my_ip_addr;
    /*------------------------------------------------------------------*/
    //나의 mac주소 구하기  
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
    my_ip_addr = ipAddress;
    myIp = my_ip_addr;
    /*----------------------------------------------------------------------*/
    /* 멤버 Ip 및 Mac 초기화 */
    myMac = Mac(my_mac_addr);
    myIp = Ip(my_ip_addr);
    cout<<"=====================나의 IP 및 MAC 주소========================"<<endl;
    cout<<"[X]My Mac Address:"<<string(myMac)<<endl;
    cout<<"[X]My Ip Address:"<<string(myIp)<<endl;
}

Mac AddressManager::getMyMac(){return myMac;}

Ip AddressManager::getMyIp(){return myIp;}

pair<Ip,Ip> AddressManager::getIpPair(int idx){return sender_target_ip_vector[idx];}

void AddressManager::addIpPair(Ip sender,Ip target){
    sender_target_ip_vector.push_back({sender,target});
    sender_target_ip_map[sender]=target;
    counter++;
}

int AddressManager::getCounter(){return this->counter;}

Mac AddressManager::getMacFromIp(Ip ip){
    return this->ip_mac_pair[ip];
}

void AddressManager::pushMac(Ip ip,Mac mac){
    this->ip_mac_pair[string(ip)]=string(mac);
}

bool AddressManager::isSenderIpExist(Ip ip){
    string ip_string = string(ip);
    for(int i=0;i<this->getCounter();i++){
        pair<Ip,Ip> ip_pair = sender_target_ip_vector[i];
        string sender_ip = string(ip_pair.first);
        if(ip_string==sender_ip) return true;
    }
    return false;
}

Ip AddressManager::getTipFromSip(Ip ip){
    return sender_target_ip_map[ip];
}