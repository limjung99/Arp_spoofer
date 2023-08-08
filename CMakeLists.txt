PROJECT("arp_spoofer")

SET( CMAKE_BUILD_TYPE Debug ) 

ADD_EXECUTABLE(arp_spoofer.out  main.cpp mac.cpp ip.cpp ethhdr.cpp arphdr.cpp)

target_link_libraries(arp_spoofer.out pcap)
