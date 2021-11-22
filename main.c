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
    uint8_t  target[ETH_ALEN];	/* destination eth addr	*/
    uint8_t  source[ETH_ALEN];	/* source type addr	*/
    uint16_t type;		        /* packet type ID field	*/
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
    u_int16_t total_len;
    u_int16_t id;
    u_int16_t fragment_off;
    u_int8_t ttl;
    u_int8_t protocol;
    u_int16_t checksum;
//    u_int8_t source_address[4];
//    u_int8_t target_address[4];
    u_int32_t source_address;
    u_int32_t target_address;
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


//unsigned char string[18];
char * inet_ntoa2(u_int32_t in)
{
    static char buf[18];
    unsigned char *bytes = (unsigned char *) &in;
    snprintf (buf, 18, "%d.%d.%d.%d",
              bytes[0], bytes[1], bytes[2], bytes[3]);
    return buf;
}


//char * inet_ntoa2(u_int32_t in)
//{
//    static char buf[18];
//    return inet_ntoa2(in, buf);
//}


char * ether_ntoa2_(uint8_t *ether_addr, char *buf)
{
    sprintf (buf, "%x:%x:%x:%x:%x:%x",
             ether_addr[0], ether_addr[1], ether_addr[2], ether_addr[3], ether_addr[4], ether_addr[5]);
    return buf;
}

char * ether_ntoa2(uint8_t *ether_addr)
{
    static char buf[18];
    return ether_ntoa2_(ether_addr, buf);
}


void func_arp(unsigned char* buffer, int buffer_size)
{
    struct arphdr2 *arp_header;
    arp_header = (struct arphdr2 *) (buffer + SIZE_ETHERNET);

//    snprintf (buffer, sizeof (buffer), "%d.%d.%d.%d",
//              bytes[0], bytes[1], bytes[2], bytes[3]);
    printf("hardware_type, protocol_type, hardware_address_length, protocola_address_length, operation_code, sender_hardware_address, sender_ip_address, target_hardware_address, target_ip_address\r");

    printf("%d,  %x, %d, %d, %d, %s, %pI4, %s, %pI4\r",
           (unsigned int)arp_header->hw_type, arp_header->proto_type, (unsigned int)arp_header->hw_len,
           arp_header->proto_len, (unsigned int)arp_header->operation, ether_ntoa2(arp_header->source_mac),
           arp_header->source_ip, ether_ntoa2(arp_header->target_mac), arp_header->target_ip);

//    fprintf(logfile,"\n");
}

void func_ip(unsigned char* buffer, int buffer_size)
{
    struct iphdr2 *ip_header;
    ip_header = (struct iphdr2 *) (buffer + SIZE_ETHERNET);
//    static char source_address[18], target_address[18];
//    inet_ntoa2(ip_header->source_address, source_address);
//    inet_ntoa2(ip_header->target_address, target_address);

    printf("version, header_length, type, total_length, id, ttl, protocol, checksum, ip_source, destination\r");

    printf("%d,  %d, %d, %d, %d, %d, %d, %d, %s, %s\r",
           (unsigned int)ip_header->version, (unsigned int)ip_header->ihl, (unsigned int)ip_header->tos,
           ntohs(ip_header->total_len), (unsigned int)ip_header->id, (unsigned int)ip_header->ttl,
           (unsigned int)ip_header->protocol, ntohs(ip_header->checksum),
           inet_ntoa2(ip_header->source_address), inet_ntoa2(ip_header->source_address));

//    fprintf(logfile,"\n");
}


void func_packet(const u_char *buffer, int buffer_size) {
    int total = 0, ipv4 = 0, arp=0, ipv6 = 0;

    //Get the IP Header part of this packet , excluding the ethernet header
    struct ether_header2 *ethernet_header;  /* The ethernet header [1] */

    ethernet_header = (struct ether_header2 *) (buffer);
    ++total;
    printf("Ether Type 0x%x \n", ntohs(ethernet_header->type));
//    if (ethernet_header->type == 0x86dd){
// printf("***Ether Type %x \n", ethernet_header->type);
//    }

    switch (ntohs(ethernet_header->type)) //Check the Protocol and do accordingly...
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