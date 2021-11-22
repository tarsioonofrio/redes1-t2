/*-------------------------------------------------------------*/
/* Exemplo Socket Raw - Captura pacotes recebidos na interface */
/*-------------------------------------------------------------*/

#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <string.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/stat.h>

/* Diretorios: net, netinet, linux contem os includes que descrevem */
/* as estruturas de dados do header dos protocolos   	  	 */

#include <net/if.h>  //estrutura ifr
#include <netinet/ether.h> //header ethernet
#include <netinet/in.h> //definicao de protocolos
#include <arpa/inet.h> //funcoes para manipulacao de enderecos IP

#include <netinet/in_systm.h> //tipos de dados


/* default snap length (maximum bytes per packet to capture) */
#define BUFFER_SIZE 1518

/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN    6


/* Ethernet protocol ID's */
#define ETHERTYPE_IP_REV  0x0008  /* IP */
#define ETHERTYPE_ARP_REV  0x0608  /* Address resolution */
#define ETHERTYPE_VLAN_REV  0x0081  /* IEEE 802.1Q VLAN tagging */
#define ETHERTYPE_IPV6_REV  0xdd86  /* IP protocol version 6 */


// Atencao!! Confira no /usr/include do seu sisop o nome correto
// das estruturas de dados dos protocolos.

struct ethernet_header
{
    uint8_t  target[ETH_ALEN];
    uint8_t  source[ETH_ALEN];
    uint16_t type;
};

struct ip_header
{
#if __BYTE_ORDER == __LITTLE_ENDIAN
    unsigned int ihl:4;
    unsigned int version:4;
#elif __BYTE_ORDER == __BIG_ENDIAN
    unsigned int version:4;
    unsigned int ihl:4;
#else
#endif
    u_int8_t tos;
    u_int16_t total_len;
    u_int16_t id;
    u_int16_t fragment_off;
    u_int8_t ttl;
    u_int8_t protocol;
    u_int16_t checksum;
    u_int32_t source_address;
    u_int32_t target_address;
};

struct arp_header {
    u_int16_t hw_type;
    u_int16_t proto_type;
    u_char hw_len;
    u_char proto_len;
    u_int16_t operation;
    u_char source_hw[6];
    u_char source_ip[4];
    u_char target_hw[6];
    u_char target_ip[4];
};

struct log_files {
    FILE *ethernet;
    FILE *arp;
    FILE *ipv4;
    FILE *ipv6;
    FILE *total;
};

struct counter {
    float total;
    float ipv4;
    float arp;
    float  ipv6;
};

//unsigned char string[18];
void ip_to_string(u_int32_t in, char * buf)
{
    unsigned char *bytes = (unsigned char *) &in;
    snprintf(buf, 18, "%d.%d.%d.%d", bytes[0], bytes[1], bytes[2], bytes[3]);
}

void ip_to_string_array(uint8_t *ip_addr, char *buf[18])
{
    sprintf(buf, "%d.%d.%d.%d", ip_addr[0], ip_addr[1], ip_addr[2], ip_addr[3]);
}

void ether_to_string(uint8_t *addr, char *buf)
{
    sprintf(buf, "%x:%x:%x:%x:%x:%x", addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
}

void func_arp(const unsigned char* buffer, int buffer_size, FILE *log_file)
{
    struct arp_header *arp_header;
    arp_header = (struct arp_header *) (buffer + SIZE_ETHERNET);
    static char source_ip[18], target_ip[18], source_hw[18], target_hw[18];
    ip_to_string_array(arp_header->target_ip, target_ip);
    ip_to_string_array(arp_header->source_ip, source_ip);
    ether_to_string(arp_header->target_hw, target_hw);
    ether_to_string(arp_header->source_hw, source_hw);

    fprintf(log_file, "%d,  %x, %d, %d, %d, %s, %s, %s, %s\n",
           (unsigned int)arp_header->hw_type, arp_header->proto_type, (unsigned int)arp_header->hw_len,
           arp_header->proto_len, (unsigned int)arp_header->operation, source_hw, source_ip, target_hw, target_ip);
}

void func_ip(const unsigned char* buffer, int buffer_size, FILE *log_file)
{
    struct ip_header *ip_header;
    ip_header = (struct ip_header *) (buffer + SIZE_ETHERNET);
    static char source[18], target[18];
    ip_to_string(ip_header->target_address, target);
    ip_to_string(ip_header->source_address, source);


    fprintf(log_file, "%d,  %d, %d, %d, %d, %d, %d, %d, %s, %s\n",
           (unsigned int)ip_header->version, (unsigned int)ip_header->ihl, (unsigned int)ip_header->tos,
           ntohs(ip_header->total_len), (unsigned int)ip_header->id, (unsigned int)ip_header->ttl,
           (unsigned int)ip_header->protocol, ntohs(ip_header->checksum), source, target);
}


void func_packet(const unsigned char *buffer, int buffer_size, struct log_files* ptr_logs, struct counter *count) {
    static char source[18], target[18];
    struct ethernet_header *eth_head;
    char string[100];
    eth_head = (struct ethernet_header *) (buffer);
    ether_to_string(eth_head->target, target);
    ether_to_string(eth_head->source, source);
    count->total++;

    fprintf(ptr_logs->ethernet, "%s, %s, 0x%x\n", target, source, ntohs(eth_head->type));

    switch (ntohs(eth_head->type))
    {
        case ETHERTYPE_IP:
            count->ipv4++;
            func_ip(buffer, buffer_size, ptr_logs->ipv4);
            break;
        case ETHERTYPE_ARP:
            count->arp++;
            func_arp(buffer, buffer_size, ptr_logs->arp);
            break;
        case ETHERTYPE_IPV6:
            count->ipv6++;
            func_ip(buffer, buffer_size, ptr_logs->ipv6);
            break;
    }
    sprintf(string, "Total : %d, ipv4:  %.2f%%, arp: %.2f%%, ipv6: %.2f%%\n",
            (int)count->total, count->ipv4/count->total, count->arp/count->total, count->ipv6/count->total);
    printf(string);
    fprintf(ptr_logs->total, string);
}



int main(int argc, char *argv[]) {
    unsigned char buffer[BUFFER_SIZE]; // buffer de recepcao
    int sockd;
    int on;
    struct ifreq ifr;

    int saddr_size, buffer_size;
    struct log_files logs;
    struct log_files *ptr_logs = &logs;
    struct counter count;
    count.arp=0;
    count.ipv4=0;
    count.ipv6=0;
    count.total=0;

    struct stat st = {0};
    if (stat("logs", &st) == -1) {
        mkdir("logs", 0777);
    }

    logs.ethernet = fopen("logs/ethernet.txt", "w");
    logs.arp = fopen("logs/arp.txt", "w");
    logs.ipv4 = fopen("logs/ipv4.txt", "w");
    logs.ipv6 = fopen("logs/ipv6.txt", "w");
    logs.total = fopen("logs/total.txt", "w");
    fprintf(logs.ethernet, "target_hw_addr, source_hw_addr, type\n");
    fprintf(logs.arp, "hw_type, proto_type, hw_addr_len, proto_addr_len, op_code, source_hw_addr, source_ip_addr, "
           "target_hw_addr, target_ip_addr\n");
    fprintf(logs.ipv4, "version, header_length, type, total_length, id, ttl, protocol, checksum, ip_source, destination\n");

    /* Criacao do socket. Todos os pacotes devem ser construidos a partir do protocolo Ethernet. */
    /* De um "man" para ver os parametros.*/
    /* htons: converte um short (2-byte) integer para standard network byte order. */
    if ((sockd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) {
        printf("Erro na criacao do socket.\n");
        exit(1);
    }

    // O procedimento abaixo eh utilizado para "setar" a interface em modo promiscuo
    strcpy(ifr.ifr_name, "eth0");
    if (ioctl(sockd, SIOCGIFINDEX, &ifr) < 0)
        printf("erro no ioctl!");
    ioctl(sockd, SIOCGIFFLAGS, &ifr);
    ifr.ifr_flags |= IFF_PROMISC;
    ioctl(sockd, SIOCSIFFLAGS, &ifr);

    // recepcao de pacotes
    while (1) {
        buffer_size = recv(sockd, (char *) &buffer, sizeof(buffer), 0x0);
        func_packet(buffer, buffer_size, ptr_logs, &count);
    }
}