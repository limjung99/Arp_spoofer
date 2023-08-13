#include "pch.h"
#include "ip.h"
#include "mac.h"
using namespace std;
/*
	Singleton Manager Class
*/
class AddressManager{
	private:
		static AddressManager* instance;
		Mac myMac;
		Ip myIp;
		map<string,Mac> ipNmac;
		vector<pair<Ip,Ip>> senderNtarget;
	public:
        static AddressManager* getInstacne();
		void initState(char* dev);
		map<string,Mac> getIpMac(){return ipNmac;}
		void addIpMac(Ip ip,Mac mac){ipNmac[string(ip)]=mac;}
		vector<pair<Ip,Ip>> getSenTar(){ return senderNtarget;}
		void addSenTar(Ip sen,Ip tar){senderNtarget.push_back({sen,tar});}
		int getSize(){return senderNtarget.size();}
		Mac getMyMac(){return myMac;}
		Ip getMyIp(){return myIp;}
};