#include <sys/socket.h> 
#include <netpacket/packet.h> 
#include <net/ethernet.h>
#include <stdio.h>
#include <errno.h>
#include <sys/types.h>
#include <ifaddrs.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <linux/if_ether.h>
#include <netinet/ether.h>
#include <stdlib.h>

int main() {
    int packet_socket;
    //get list of interface addresses. This is a linked list. Next
    //pointer is in ifa_next, interface name is in ifa_name, address is
    //in ifa_addr. You will have multiple entries in the list with the
    //same name, if the same interface has multiple addresses. This is
    //common since most interfaces will have a MAC, IPv4, and IPv6
    //address. You can use the names to match up which IPv4 address goes
    //with which MAC address.
    u_int8_t macAddress[4][6];
    struct macAddr {
        u_int8_t mac[6];
    };

    struct ifaddrs *ifaddr, *tmp;
    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        return 1;
    }

    fd_set sockets; // a set of file descriptors
    FD_ZERO(&sockets);


    //have the list, loop over the list
    for (tmp = ifaddr; tmp != NULL; tmp = tmp->ifa_next) {
        //Check if this is a packet address, there will be one perss
        //interface.  There are IPv4 and IPv6 as well, but we don't care
        //about those for the purpose of enumerating interfaces. We can
        //use the AF_INET addresses in this list for example to get a list
        //of our own IP addresses
        if (tmp->ifa_addr->sa_family == AF_PACKET) {
            printf("Interface: %s\n", tmp->ifa_name);
            //create a packet socket on interface r?-eth1

            if (strncmp(tmp->ifa_name, "lo", 2)) {
                struct sockaddr_ll * sockaddr = (sockaddr_ll *)(tmp->ifa_addr);
                struct macAddr macaddr;
                memcpy(macaddr.mac, sockaddr->sll_addr, 6);
                printf("Our MAC: %s\n", ether_ntoa((struct ether_addr *) macaddr.mac));

                char interfaceNumber = tmp->ifa_name[strlen(tmp->ifa_name) - 1];
                memcpy(macAddress[atoi(&interfaceNumber)], macaddr.mac, 6 * sizeof(u_int8_t));
                printf("Added mac address : %s\n", ether_ntoa((struct ether_addr *) macAddress[atoi(&interfaceNumber)]));


                printf("Creating Socket on interface %s\n", tmp->ifa_name);
                //create a packet socket
                //AF_PACKET makes it a packet socket
                //SOCK_RAW makes it so we get the entire packet
                //could also use SOCK_DGRAM to cut off link layer header
                //ETH_P_ALL indicates we want all (upper layer) protocols
                //we could specify just a specific one
                packet_socket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
                if (packet_socket < 0) {
                    perror("socket");
                    return 2;
                }
                //Bind the socket to the address, so we only get packets
                //recieved on this specific interface. For packet sockets, the
                //address structure is a struct sockaddr_ll (see the man page
                //for "packet"), but of course bind takes a struct sockaddr.
                //Here, we can use the sockaddr we got from getifaddrs (which
                //we could convert to sockaddr_ll if we needed to)
                if (bind(packet_socket, tmp->ifa_addr, sizeof(struct sockaddr_ll)) == -1){
                    perror("bind");
                }
                FD_SET(packet_socket, &sockets);
            }
        }
    }

    //loop and recieve packets. We are only looking at one interface,
    //for the project you will probably want to look at more (to do so,
    //a good way is to have one socket per interface and use select to
    //see which ones have data)
    printf("Ready to recieve now\n");
    while (1) {
        char packet[1500];
        struct sockaddr_ll sourceAddr;
        socklen_t recvaddrlen = sizeof(struct sockaddr_ll);

        fd_set tmp_set = sockets;
        select(FD_SETSIZE, &tmp_set, NULL, NULL, NULL);
        //we can use recv, since the addresses are in the packet, but we
        //use recvfrom because it gives us an easy way to determine if
        //this packet is incoming or outgoing (when using ETH_P_ALL, we
        //see packets in both directions. Only outgoing can be seen when
        //using a packet socket with some specific protocol)

        // int n = recvfrom(packet_socket, buf, 1500, 0, (struct sockaddr*) &sourceAddr, &recvaddrlen);

        //ignore outgoing packets (we can't disable some from being sent
        //by the OS automatically, for example ICMP port unreachable
        //messages, so we will just ignore them here)
        if (sourceAddr.sll_pkttype == PACKET_OUTGOING)
            continue;
        //start processing all others

        for (int i = 0; i < FD_SETSIZE; i++) {
            if (FD_ISSET(i, &tmp_set)) {
                int n = recvfrom(i, packet, 1500, 0, (struct sockaddr*) &sourceAddr, &recvaddrlen);
                printf("Got a %d byte packet from socket %d\n", n, i);

                if (htons(sourceAddr.sll_protocol) == ETH_P_ARP) {
                    // do arp stuff
                    printf("ARP PACKET!!!\n");
                } else {
                    // do icmp stuff
                    printf("NOT ARP PACKET!!!\n");
                    char etherHeader[26];
                    strncpy(etherHeader, packet, 26);

                    char ipHeader[32];
                    strncpy(ipHeader, packet + 26, 32);

                    char icmpHeader[8];
                    strncpy(icmpHeader, packet + (26+32), 8);


                    printf("ether source: %s  ether dest:%s\n", etherHeader+8, etherHeader+14);
                    char swapMacs[6];
                    memcpy(swapMacs, etherHeader + 8, 6);
                    memcpy(etherHeader + 8, etherHeader + 14, 6);
                    memcpy(etherHeader + 14, swapMacs, 6);
                    printf("ether source: %s  ether dest:%s\n", etherHeader+8, etherHeader+14);
                }
            }
        }

        //what else to do is up to you, you can send packets with send,
        //just like we used for TCP sockets (or you can use sendto, but it
        //is not necessary, since the headers, including all addresses,
        //need to be in the buffer you are sending)

    }
    //free the interface list when we don't need it anymore
    freeifaddrs(ifaddr);
    //exit
    return 0;
}
