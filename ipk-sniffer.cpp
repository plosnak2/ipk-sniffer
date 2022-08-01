#include <iostream>
#include <getopt.h>
#include <string.h>
#include <pcap.h>  
#include<netinet/if_ether.h>
#include<netinet/in.h>
#include<netinet/ip.h>
#include<netinet/ip6.h>
#include<netinet/tcp.h>
#include<netinet/udp.h>
#include<netinet/ether.h>
#include <netinet/ip_icmp.h>

using namespace std;

// Global variables for parameters storing
bool interface_flag_only = false;
bool interface_flag = false;
char interface [256] = "";
bool port_flag = false;
char port [256] = "";
bool tcp_flag = false;
bool udp_flag = false;
bool arp_flag = false;
bool icmp_flag = false;
int number_packets = 1;
bool all_protocols = false;


// defining ether types: IPv4, IPv6, ARP
#define ETHER_TYPE_IPV4 2048;
#define ETHER_TYPE_IPV6 34525;
#define ETHER_TYPE_ARP 2054;

// global variable for session handler
pcap_t *handle;

// function for controlling and handling parameters
void arg_parse(int argc, char* argv[]){
    static struct option long_options[] =
    {
        {"interface", required_argument, 0, 'i'},
        {"tcp", no_argument, 0, 't'},
        {"udp", no_argument, 0, 'u'},
        {"arp", no_argument, 0, 'a'},
        {"icmp", no_argument, 0, 'm'},
        {0,0,0,0}
    };

    int arg;
    int number_of_arguments = 0;
    while ((arg = getopt_long(argc, argv, ":i:tuamp:n:", long_options, NULL)) != -1)
    {
        switch (arg) {
            case 'i':
                interface_flag = true;
                strcpy(interface, optarg);
                number_of_arguments += 2;
                break;
            case 't':
                tcp_flag = true;
                number_of_arguments++;
                break;
            case 'u':
                udp_flag = true;
                number_of_arguments++;
                break;
            case 'a':
                arp_flag = true;
                number_of_arguments++;
                break;
            case 'm':
                icmp_flag = true;
                number_of_arguments++;
                break;
            case 'p':
                port_flag = true;
                strcpy(port, optarg);
                number_of_arguments += 2;
                break;
            case 'n':
                number_packets = atoi(optarg);
                number_of_arguments += 2;
                break;
            case ':':
                if(optopt == 'i'){
                    interface_flag_only = true;
                    number_of_arguments++;
                    break;
                }
            default:
                fprintf(stderr, "Wrong parameters\n");
                exit(EXIT_FAILURE);
        }
    }

    if(argc - 1 != number_of_arguments){
        fprintf(stderr, "Wrong parameters.\n");
        exit(EXIT_FAILURE);
    }

    if(tcp_flag == false && udp_flag == false && arp_flag == false && icmp_flag == false){
        all_protocols = true;
        tcp_flag = true;
        udp_flag = true;
        arp_flag = true;
        icmp_flag = true;
    }

    if(interface_flag == false && interface_flag_only == false) {
        fprintf(stderr, "Wrong parameters, Interface flag must be specified.\n");
        exit(EXIT_FAILURE);
    }

    if(interface_flag_only == true && argc != 2){
        fprintf(stderr, "Wrong parameters, Cant combine -i without interface with other parameters.\n");
        exit(EXIT_FAILURE);
    }

    return;
}

// function that displays all active interfaces - can be run as ./ipk-sniffer -i
void show_interfaces(){
    char err[PCAP_ERRBUF_SIZE];
    pcap_if_t* interfaces, *temp;

    // calling findalldevs function from pcap, that finds all inteerfaces
    if(pcap_findalldevs(&interfaces, err) == -1){
        fprintf(stderr, "Problem with printing interfaces, pcap_finalldevs returned err.\n");
        exit(EXIT_FAILURE);
    }

    // going through every interface and printing his name
    for(temp = interfaces; temp != NULL; temp=temp->next){
        printf("%s\n",temp->name);
    }

    return;
}

// function for openning session and setting session handler
void open_session(){
    char err[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;      /* compiled filter */
    char filter [256] = "";     /* my string filter */
    bpf_u_int32 mask, net;      /* IP of snipping device */

    
    int flag_counter = 0;
    if(arp_flag == true) flag_counter++;
    if(tcp_flag == true) flag_counter++;
    if(udp_flag == true) flag_counter++;
    if(icmp_flag == true) flag_counter++;

    /* creating filter for pcap session */
    if(port_flag == true){
        strcat(filter, "port ");
        strcat(filter, port);
        strcat(filter, " and ");
    }
        
    strcat(filter, "(");

    int temp_flag = 0;
    if(tcp_flag == true){
        temp_flag++;
        if(temp_flag == flag_counter) strcat(filter, "tcp)");
        else strcat(filter, "tcp or ");
    }

    if(udp_flag == true){
        temp_flag++;
        if(temp_flag == flag_counter) strcat(filter, "udp)");
        else strcat(filter, "udp or ");
    }

    if(icmp_flag == true){
        temp_flag++;
        if(temp_flag == flag_counter) strcat(filter, "icmp or icmp6)");
        else strcat(filter, "icmp or icmp6 or ");
    }

    if(arp_flag == true){
        temp_flag++;
        if(temp_flag == flag_counter) strcat(filter, "arp)");
        else strcat(filter, "arp or ");
    }
     
    
    /* function for getting netmask for device */
    if(pcap_lookupnet(interface, &net, &mask, err) == -1){
        fprintf(stderr, "Couldnt get netmask - error in pcap_lookupnet.\n");
        exit(EXIT_FAILURE);
    }

    /* function for openning device to listen to */
    handle = pcap_open_live(interface, BUFSIZ, 1, 1000, err);
    if(handle == NULL){
        fprintf(stderr, "Couldnt open interface - error in pcap_open_live: %s\n", err);
        exit(EXIT_FAILURE);
    }

    /* compiling filter into acceptable format */
    if(pcap_compile(handle, &fp, filter, 0, net) == -1){
        fprintf(stderr, "Couldnt transform filter into acceptable format: %s\n", err);
        exit(EXIT_FAILURE);
    }

    /* applying filter from previous step on interface */
    if(pcap_setfilter(handle, &fp) == -1){
        fprintf(stderr, "Couldnt apply filter on interface: %s\n", err);
        exit(EXIT_FAILURE);
    }

    return;
}

/* function for printing time in RFC3339 format */
void print_time(){
    /* first part is for date and time of a time */
    /* Code inspiride by https://stackoverflow.com/a/48772690
       question: I'm trying to build an RFC3339 timestamp in C. How do I get the timezone offset?
       author URL: https://stackoverflow.com/users/2410359/chux-reinstate-monica */
    time_t now;
    time(&now);
    struct tm *format = localtime(&now);
    char buf[100];
    size_t len = strftime(buf, sizeof buf - 1, "%FT%T", format);
    /* printing date and time */
    printf("%s", buf);

    /* second part is for miliseconds */
    struct timeval milisec;
    gettimeofday(&milisec, NULL);
    printf(".%03ld", milisec.tv_usec/1000);

    /* thirs part is for timezone */
    /* took this part from the internet -> in documentation */
    char buf2[100];
    len = strftime(buf2, sizeof buf2 - 1, "%z", format);
    if (len > 1) {
        char minute[] = { buf2[len-2], buf2[len-1], '\0' };
        sprintf(buf2 + len - 2, ":%s", minute);
    }
    printf("%s ", buf2);
}

/* function for printing data of packet */
void print_packet(const u_char *packet, int size){
    // variable for counting -> 16 charcters on 1 line
    int line_count = 1;
    // variable for counting letters  -> to add spaces at the last line
    int count_letters = 0;
    printf("0x0000: ");
    
    // cycle through packet data
    for(int i = 0; i < size; i++){
        // printing hexa value
        printf("%02x ", (unsigned char) packet[i]);
        // every 16 chars -> print 0x0... format ... + 16 char values
        if((i+1) % 16 == 0){
            printf(" ");
            for(int j = 15; j >= 0; j--){
                count_letters++;
                if(isprint(packet[i-j]))                
                    printf("%c",packet[i-j]);          
                else
                    printf(".");          
                
            }
            printf("\n0x%04x: ", line_count);
        }
        line_count++;
    }

    // this is for last line, when size % 16 != 0
    int letters;
    if(count_letters == size){
        printf("\n");
    } else {
        letters = size - count_letters;
        int spaces = 16 - letters;

        for(int i = 0; i < spaces; i++){
            printf("   ");
        }
        printf(" ");

        for(int i = size-letters; i < size; i++){
            if(isprint(packet[i]))                
                    printf("%c",packet[i]);          
                else
                    printf(".");
        }
        printf("\n");
    }


    return; 
}

/* function for handling packet */
void handle_packet (u_char *args, const struct pcap_pkthdr *header, const u_char *packet){

    print_time();

    bool ipv4 = false;
    bool ipv6 = false;
    bool arp = false;
    
    // getting ether type from packet
    struct ether_header *ethdr = (struct ether_header *)packet;
    int ether_type = ntohs(ethdr->ether_type);

    if(ether_type == 2048){
        ipv4 = true;
    } else if (ether_type == 2054){
        arp = true;
    } else if (ether_type == 34525){
        ipv6 = true;
    } else {
        fprintf(stderr, "Wrong ether type.\n");
        exit(EXIT_FAILURE);
    }

    
    if(ipv4 == true){
        // getting header length from ip header
        int ip_header_len;
        struct iphdr* ip_header = (struct iphdr *) (packet + sizeof(struct ether_header));
        ip_header_len = ip_header->ihl * 4;

        // getting source and dest adresses
        char source [256];
        char dest [256];

        strcpy(source, inet_ntoa(*(in_addr*)&ip_header->saddr));
        strcpy(dest, inet_ntoa(*(in_addr*)&ip_header->daddr));

        // taking care of IPv4 protocols
        switch(ip_header->protocol){
            case IPPROTO_TCP:
                {
                    // handling tcp IPv4 protocol
                    struct tcphdr* tcp_header = (struct tcphdr *)(packet + sizeof(struct ether_header) + ip_header_len);
                    printf("%s : %d > %s : %d, length %d bytes, TCP (IPv4)\n", source, ntohs(tcp_header->source), dest, ntohs(tcp_header->dest), header->len);
                    print_packet(packet, header->caplen);
                    break;
                }

            case IPPROTO_UDP:
                {
                    // handling udp IPv4 protocol
                    struct udphdr* udp_header = (struct udphdr *)(packet + sizeof(struct ether_header) + ip_header_len);
                    printf("%s : %d > %s : %d, length %d bytes. UDP (IPv4)\n", source, ntohs(udp_header->source), dest, ntohs(udp_header->dest), header->len);
                    print_packet(packet, header->caplen);
                    break;
                }
            
            case IPPROTO_ICMP:
                {
                    // handling icmp IPv4 protocol
                    printf("%s > %s, length %d bytes ICMPv4\n", source, dest, header->len);
                    print_packet(packet, header->caplen);
                    break;
                }
            
            default:
                {
                    fprintf(stderr, "Wrong protocol.\n");
                    exit(EXIT_FAILURE);
                }
        }

    } else if (arp == true){
    
        struct ether_arp * arp_packet = (struct ether_arp *)(packet + sizeof(struct ether_header));
        //printf("%d\n", ntohs(arp_packet->arp_op));

        // SENDER IP ADRESS
        struct in_addr* arp_spa = (struct in_addr*) arp_packet->arp_spa;
        printf("%s (", inet_ntoa(*arp_spa));

        // SENDER MAC ADDRESS
        for(int i = 0; i < 5; i++){
            printf("%02x:", arp_packet->arp_sha[i]);
        }

        printf("%02x) > ", arp_packet->arp_sha[5]);

        // TARGET IP ADRESS
        struct in_addr* arp_tpa = (struct in_addr *) arp_packet->arp_tpa;
        printf("%s (", inet_ntoa(*arp_tpa));

        // TARGET MAC ADRESS
        for(int i = 0; i < 5; i++){
            printf("%02x:", arp_packet->arp_tha[i]);
        }

        // REQUEST OR REPLY
        char arp_opcode[256];
        if(ntohs(arp_packet->arp_op) == 1){
            strcpy(arp_opcode, "request");
        } else {
            strcpy(arp_opcode, "reply");
        }
        
        printf("%02x), length %d bytes, ARP packet (%s) \n", arp_packet->arp_tha[5], header->len, arp_opcode);
        print_packet(packet, header->caplen);
    } else {
        // IPv6 -> this part work only for IPv6 adresses, that has no extension headers, only classic IPv6 + protocol UDP/TCP/ICMP
        struct ip6_hdr* ip6_header = (struct ip6_hdr*)(packet + sizeof(struct ether_header));
        char source [256];
        char dest [256];

        // Storing destination and source adresses
        inet_ntop(AF_INET6, &(ip6_header->ip6_src), source, INET6_ADDRSTRLEN);
        inet_ntop(AF_INET6, &(ip6_header->ip6_dst), dest, INET6_ADDRSTRLEN);
        
        // Storing protocol type : UDP/ TCP/ ICMP
        int protocol = ip6_header->ip6_ctlun.ip6_un1.ip6_un1_nxt;
        switch(protocol){
            case IPPROTO_TCP:
                {
                    // handling tcp IPv6 protocol
                    struct tcphdr* tcp_header = (struct tcphdr *)(packet + sizeof(struct ether_header) + 40);
                    printf("%s : %d > %s : %d, length %d bytes, TCP (IPv6)\n", source, ntohs(tcp_header->source), dest, ntohs(tcp_header->dest), header->len);
                    print_packet(packet, header->caplen);
                    break;
                }

            case IPPROTO_UDP:
                {   
                    // handling udp IPv4 protocol
                    struct udphdr* udp_header = (struct udphdr *)(packet + sizeof(struct ether_header) + 40);
                    printf("%s : %d > %s : %d, length %d bytes, UDP (IPv6)\n", source, ntohs(udp_header->source), dest, ntohs(udp_header->dest), header->len);
                    print_packet(packet, header->caplen);
                    break;
                }
            
            case IPPROTO_ICMPV6:
                {
                    // handling ICMPv6 protocols
                    printf("%s > %s, length %d bytes, ICMPv6\n", source, dest, header->len);
                    print_packet(packet, header->caplen);
                    break;
                }
            
            default:
                {
                    // other protocol in IPv6 beside udp/tcp/icmp, should never come here
                    fprintf(stderr, "Wrong protocol.\n");
                    exit(EXIT_FAILURE);
                }
        }

    }
    
    printf("\n");
    return;
}


int main(int argc, char*argv[]) {
    arg_parse(argc, argv);

    if(interface_flag_only){
        show_interfaces();
        exit(EXIT_SUCCESS);
    } else {
        open_session();
    }
    
    // function that get a me number_packets packets and i am handling them in handle_packet func
    pcap_loop(handle, number_packets, handle_packet, NULL);
    return 0;
}