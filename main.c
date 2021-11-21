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

/* Diretorios: net, netinet, linux contem os includes que descrevem */
/* as estruturas de dados do header dos protocolos   	  	 */

#include <net/if.h>  //estrutura ifr
#include <netinet/ether.h> //header ethernet
#include <netinet/in.h> //definicao de protocolos
#include <arpa/inet.h> //funcoes para manipulacao de enderecos IP

#include <netinet/in_systm.h> //tipos de dados


int is_little_endian() {
    short int number = 0x1;
    char *numPtr = (char *) &number;
    return (numPtr[0] == 1);
}


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

unsigned char buffer[BUFFER_SIZE]; // buffer de recepcao

int sockd;
int on;
struct ifreq ifr;


// ethernet.h
struct ether_header2
{
    uint8_t  ether_dhost[ETH_ALEN];	/* destination eth addr	*/
    uint8_t  ether_shost[ETH_ALEN];	/* source ether addr	*/
    uint16_t ether_type;		        /* packet type ID field	*/
};

//ip.h
struct iphdr2
{
#if __BYTE_ORDER == __LITTLE_ENDIAN
    unsigned int ihl:4;
    unsigned int version:4;
#elif __BYTE_ORDER == __BIG_ENDIAN
    unsigned int version:4;
    unsigned int ihl:4;
#else
# error        "Please fix <bits/endian.h>"
#endif
    u_int8_t tos;
    u_int16_t tot_len;
    u_int16_t id;
    u_int16_t frag_off;
    u_int8_t ttl;
    u_int8_t protocol;
    u_int16_t check;
    u_int32_t saddr;
    u_int32_t daddr;
    /*The options start here. */
};

//if_aro.h
struct arphdr2 {
    u_int16_t hw_type;    /* Hardware Type           */
    u_int16_t proto_type;    /* Protocol Type           */
    u_char hw_len;        /* Hardware Address Length */
    u_char proto_len;        /* Protocol Address Length */
    u_int16_t operation;     /* Operation Code          */
    u_char source_mac[6];      /* Sender hardware address */
    u_char source_ip[4];      /* Sender IP address       */
    u_char target_mac[6];      /* Target hardware address */
    u_char target_ip[4];      /* Target IP address       */
};


char * sprintf_ether(uint8_t *ether_addr)
{
    static char buf[18];
    sprintf (buf, "%x:%x:%x:%x:%x:%x",
             ether_addr[0], ether_addr[1], ether_addr[2], ether_addr[3], ether_addr[4], ether_addr[5]);
    return buf;
}

void func_arp(unsigned char* buffer, int buffer_size)
{
    struct arphdr2 *arp_header;
    struct sockaddr_in ip_source, ip_dest;
    arp_header = (struct arphdr2 *) (buffer + SIZE_ETHERNET);

    memset(&ip_source, 0, sizeof(ip_source));
    ip_source.sin_addr.s_addr = arp_header->saddr;

    memset(&ip_dest, 0, sizeof(ip_dest));
    ip_dest.sin_addr.s_addr = arp_header->daddr;
    printf("hardware_type, protocol_type, hardware_address_length, protocola_address_length, operation_code, sender_hardware_address, sender_ip_address, target_hardware_address, target_ip_address\r");

    printf("%d,  %x, %d, %d, %d, %s, %pI4, %s, %pI4\r",
           (unsigned int)arp_header->hw_type, arp_header->proto_type, (unsigned int)arp_header->hw_len,
           arp_header->proto_len, (unsigned int)arp_header->operation, sprintf_ether(arp_header->source_mac),
           arp_header->source_ip, sprintf_ether(arp_header->target_mac), arp_header->target_ip);

//    fprintf(logfile,"\n");
}

void func_ip(unsigned char* buffer, int buffer_size)
{
    struct iphdr2 *ip_header;
    struct sockaddr_in ip_source, ip_dest;
    ip_header = (struct iphdr2 *) (buffer + SIZE_ETHERNET);

    memset(&ip_source, 0, sizeof(ip_source));
    ip_source.sin_addr.s_addr = ip_header->saddr;

    memset(&ip_dest, 0, sizeof(ip_dest));
    ip_dest.sin_addr.s_addr = ip_header->daddr;
    printf("version, header_length, type, total_length, id, ttl, protocol, checksum, ip_source, destination\r");

    printf("%d,  %d, %d, %d, %d, %d, %d, %d, %pI4, %pI4\r",
           (unsigned int)ip_header->version, (unsigned int)ip_header->ihl, (unsigned int)ip_header->tos,
           ntohs(ip_header->tot_len),  (unsigned int)ip_header->id, (unsigned int)ip_header->ttl,
           (unsigned int)ip_header->protocol, ntohs(ip_header->check), ip_header->saddr, ip_header->daddr);

//    fprintf(logfile,"\n");
}


void func_packet(const u_char *buffer, int buffer_size) {
    int total = 0, ipv4 = 0, arp=0, ipv6 = 0;

    //Get the IP Header part of this packet , excluding the ethernet header
    struct ether_header2 *ethernet_header;  /* The ethernet header [1] */

    ethernet_header = (struct ether_header2 *) (buffer);
    ++total;
    printf("Ether Type 0x%x \n", ntohs(ethernet_header->ether_type));
//    if (ethernet_header->type == 0x86dd){
// printf("***Ether Type %x \n", ethernet_header->type);
//    }

    switch (ntohs(ethernet_header->ether_type)) //Check the Protocol and do accordingly...
    {
        case ETHERTYPE_IP:
            ++ipv4;
            func_ip(buffer, buffer_size);
            break;
        case ETHERTYPE_ARP:
            ++arp;
            break;
        case ETHERTYPE_IPV6:
            ++ipv6;
            func_ip(buffer, buffer_size);
            break;
    }
    printf("Total : %d, ipv4: %d, arp: %d, ipv6: %d\r", total, ipv4, arp, ipv6);
}



int main(int argc, char *argv[]) {
    int saddr_size, buffer_size;

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
        func_packet(buffer, buffer_size);

        // impressão do conteudo - exemplo Endereco Destino e Endereco Origem
        printf("MAC Destino: %x:%x:%x:%x:%x:%x \n", buffer[0], buffer[1], buffer[2], buffer[3], buffer[4], buffer[5]);
        printf("MAC Origem:  %x:%x:%x:%x:%x:%x \n\n", buffer[6], buffer[7], buffer[8], buffer[9], buffer[10],
               buffer[11]);
    }
}