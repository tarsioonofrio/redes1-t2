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
/* as estruturas de dados do header dos protocolos   	  	        */

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


// Atencao!! Confira no /usr/include do seu sisop o nome correto
// das estruturas de dados dos protocolos.

unsigned char buffer[BUFFER_SIZE]; // buffer de recepcao

int sockd;
int on;
struct ifreq ifr;

int total = 0, tcp = 0, udp = 0, icmp = 0, others = 0, igmp = 0, ipv4 = 0, ipv6 = 0;

/* Ethernet header */
typedef struct {
    u_char  target_host[ETHER_ADDR_LEN];    /* destination host address */
    u_char  source_host[ETHER_ADDR_LEN];    /* source host address */
    u_short type;                     /* IP? ARP? RARP? etc */
} struct_ethernet_header;


typedef struct {
    u_char version;                 /* version << 4 | header length >> 2 */
    u_char tos;                 /* type of service */
    u_short tos_length;                 /* total length */
    u_short id;                  /* identification */
    u_short offset;                 /* fragment offset field */
#define IP_RF 0x8000            /* reserved fragment flag */
#define IP_DF 0x4000            /* dont fragment flag */
#define IP_MF 0x2000            /* more fragments flag */
#define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
    u_char ttl;                 /* time to live */
    u_char protocol;                   /* protocol */
    u_short checksum;                 /* checksum */
    struct in_addr ip_src, ip_dst;  /* source and dest address */
} struct_ip_header;



void detect_packet(const u_char *buffer, int size) {
    //Get the IP Header part of this packet , excluding the ethernet header
    const struct_ethernet_header *ethernet_header;  /* The ethernet header [1] */
    const struct_ip_header *ip_header;

    ethernet_header = (struct_ethernet_header *) (buffer);
    ip_header = (struct_ip_header *) (buffer + SIZE_ETHERNET);
    ++total;
    printf("Ether Type x%x \n", ethernet_header->type);
    switch (ip_header->protocol) //Check the Protocol and do accordingly...
    {
        case 1:  //ICMP Protocol
            ++icmp;
//            print_icmp_packet( buffer , size);
            break;

        case 2:  //IGMP Protocol
            ++igmp;
            break;

        case 6:  //TCP Protocol
            ++tcp;
//            print_tcp_packet(buffer , size);
            break;

        case 17: //UDP Protocol
            ++udp;
//            print_udp_packet(buffer , size);
            break;

        default: //Some Other Protocol like ARP etc.
            ++others;
            break;
    }
    printf("TCP : %d   UDP : %d   ICMP : %d   IGMP : %d   Others : %d   Total : %d\r", tcp, udp, icmp, igmp, others,
           total);
}

int main(int argc, char *argv[]) {
    int saddr_size, data_size;

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
        data_size = recv(sockd, (char *) &buffer, sizeof(buffer), 0x0);
        detect_packet(buffer, data_size);

        // impressão do conteudo - exemplo Endereco Destino e Endereco Origem
        printf("MAC Destino: %x:%x:%x:%x:%x:%x \n", buffer[0], buffer[1], buffer[2], buffer[3], buffer[4], buffer[5]);
        printf("MAC Origem:  %x:%x:%x:%x:%x:%x \n\n", buffer[6], buffer[7], buffer[8], buffer[9], buffer[10],
               buffer[11]);
    }
}