#include "pch.h"
#include "ip.h"
#include "mac.h"
using namespace std;

/*
	ArpSpoofer Class
*/
class AddressManager{
	private:
        string interfacename;
		Ip myIp; /*attacker Ip struct*/
		Mac myMac; /*attacker Mac struct*/
		vector<pair<Ip,Ip>> sender_target_ip_vector; /* sender ip 인스턴스와 target ip 인스턴스를 매핑하여 vector에 저장 */
		map<Ip,Ip> sender_target_ip_map;/* sender ip와 target ip 매핑 */
		map<Ip,Mac> ip_mac_pair; /* ip주소와 mac주소 매핑 */
        int counter = 0; /* sender and target pair size */
	public:
        AddressManager(string interfacename);
		Mac getMyMac();
		Ip getMyIp();
        pair<Ip,Ip> getIpPair(int idx); /* idx번째 Ip 인스턴스 pair를 가져오는 메소드 */
        void addIpPair(Ip sender,Ip target); /* sender 와 target의 Ip인스턴스를 추가하는 메소드 */
        int getCounter();
		Mac getMacFromIp(Ip ip); /* IP 구조체에 대응하는 mac string을 리턴하는 메소드 */
		void pushMac(Ip ip,Mac mac); /* Ip에 해당하는 mac을 ip_mac_pair에 매핑시켜주는 메소드 */
		bool isSenderIpExist(Ip ip);
		Ip getTipFromSip(Ip ip);
};