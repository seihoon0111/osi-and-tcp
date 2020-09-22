#include <pcap.h>
#include <stdio.h>
#include <stdint.h>
#include <libnet.h>
#include <netinet/in.h>



void usage() {
    printf("syntax: pcap-test <interface>\n");
    printf("sample: pcap-test wlan0\n");
}


void eth_mac_address(struct libnet_ethernet_hdr eth){
    
    printf("src mac : ");

    for(int i=0;i<ETHER_ADDR_LEN -1;i++){
        printf("%02x:",eth.ether_shost[i]);
    }
    printf("%02x\n",eth.ether_shost[ETHER_ADDR_LEN-1]);

    printf("dst mac : ");

    for(int i=0;i<ETHER_ADDR_LEN -1;i++){
        printf("%02x:",eth.ether_dhost[i]);
    }
    printf("%02x\n",eth.ether_dhost[ETHER_ADDR_LEN-1]);

}

void ip_src_dst(struct libnet_ipv4_hdr ip){
    uint32_t src_ip = ntohl(ip.ip_src.s_addr);
    uint32_t dst_ip = ntohl(ip.ip_dst.s_addr);

    printf("src ip : ");
    printf("%d.%d.%d.%d\n",src_ip>>24,(src_ip>>16)&(0xff),(src_ip>>8)&(0xff),(src_ip)&(0xff));

    printf("dst ip : ");
    printf("%d.%d.%d.%d\n",dst_ip>>24,(dst_ip>>16)&(0xff),(dst_ip>>8)&(0xff),(dst_ip)&(0xff));
}

void tcp_port(struct libnet_tcp_hdr tcp){

    printf("src port : %d\n",ntohs(tcp.th_sport));
    printf("dst port : %d\n",ntohs(tcp.th_dport));

}



int print_imf(const u_char* packet, uint32_t length){
    struct libnet_ethernet_hdr eth;
    struct libnet_ipv4_hdr ip;
    struct libnet_tcp_hdr tcp;

    memcpy(&eth, packet, LIBNET_ETH_H);
    memcpy(&ip,  packet + LIBNET_ETH_H, LIBNET_IPV4_H);
    memcpy(&tcp, packet + LIBNET_ETH_H + LIBNET_IPV4_H, LIBNET_TCP_H);

    if(ip.ip_p != 0x06){
        printf("not TCP\n");
        return 0;
    }//tcp check

    //print eth imf
    eth_mac_address(eth);

    //print ip imf
    ip_src_dst(ip);

    //print tcp imf
    tcp_port(tcp);

    //payload data
    uint32_t size=length-(LIBNET_ETH_H + LIBNET_IPV4_H + tcp.th_off*4);
    uint8_t payload[16];
    printf("data size : %d \n",size);
    if(size==0){
        printf("\n");
        return 0;
    }
    if(size>16){
        size=16;
    }
    memcpy(payload,packet + LIBNET_ETH_H + LIBNET_IPV4_H + tcp.th_off*4, size);
    printf("payload : ");
    for(int i=0;i<size;i++){
        printf("%02x ",payload[i]);
    }

    printf("\n");
    return 0;
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        usage();
        return -1;
    }

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "pcap_open_live(%s) return nullptr - %s\n", dev, errbuf);
        return -1;
    }

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }
        printf("%u bytes captured\n", header->caplen);
        print_imf(packet, header->caplen);
        printf("-------------------------------------\n");
    }

    pcap_close(handle);
}