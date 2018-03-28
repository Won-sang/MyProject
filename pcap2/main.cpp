#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>

 int main(int argc, char *argv[])
 {
     typedef struct Ethernet_Header
     {
         u_char des[6];
         u_char src[6];
         short int ptype; // protocal type
     }Ethernet_Header;

     typedef struct ipaddress
     {
         u_char ip1;
         u_char ip2;
         u_char ip3;
         u_char ip4;
     }ip;

     typedef struct IPHeader
     {
         u_char HeaderLength : 4;
         u_char Version : 4;
         u_char TypeOfService;
         u_short TotalLength;
         u_short ID;
         u_short FlagOffset;

         u_char TimeToLive;
         u_char Protocol;
         u_short checksum;
         ipaddress SenderAddress;
         ipaddress DestinationAddress;
         u_int Option_Padding;

     }IPHeader;

     typedef struct TCPHeader
     {
         u_short sport;
         u_short dport;
         u_int seqnum;
         u_int acknum;
         u_char th_off;
#define TH_OFF(TCP)      (((TCP)->th_off & 0xf0) >> 4)
         u_char flags;
         u_short win;
         u_short crc;
         u_short urgptr;
     }TCPHeader;

     const u_char *payload;                    /* Packet payload */
     int size_payload;

    pcap_t *handle;			/* Session handle */
    char *dev;			/* The device to sniff on */
    char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
    bpf_u_int32 mask;		/* Our netmask */
    bpf_u_int32 net;		/* Our IP */
    struct pcap_pkthdr header;	/* The header that pcap gives us */
    const u_char *packet;		/* The actual packet */


    /* Define the device */
    dev = pcap_lookupdev(errbuf);
    if (dev == NULL) {
        fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
        return(2);
    }
    /* Find the properties for the device */
    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
        net = 0;
        mask = 0;
    }
    /* Open the session in promiscuous mode */
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return(2);
    }

    /* Grab a packet */
    for(int i=0;i<20;i++){
    packet = pcap_next(handle, &header);

    Ethernet_Header *EH = (Ethernet_Header *)packet;
    short int type = ntohs(EH->ptype);

    printf("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n");
    printf("Ethernet Header\n");
    printf("Dst Mac Address : %02x-%02x-%02x-%02x-%02x-%02x\n", EH->src[0], EH->src[1], EH->src[2], EH->src[3], EH->src[4], EH->src[5]);
    printf("Src Mac Address : %02x-%02x-%02x-%02x-%02x-%02x\n", EH->des[0], EH->des[1], EH->des[2], EH->des[3], EH->des[4], EH->des[5]);

    if (type == 0x0800)
    {
        IPHeader *IH = (IPHeader*)(packet + 14);
        printf("\nIP Header\n");
        printf("Src IP Address : %d.%d.%d.%d\n", IH->SenderAddress.ip1, IH->SenderAddress.ip2, IH->SenderAddress.ip3, IH->SenderAddress.ip4);
        printf("Dst IP Address : %d.%d.%d.%d\n", IH->DestinationAddress.ip1, IH->DestinationAddress.ip2, IH->DestinationAddress.ip3, IH->DestinationAddress.ip4);
        printf("Ip Header len : %d\n", (IH->HeaderLength)*4);
        if (IH->Protocol == 6)
        {
            TCPHeader *TCP = (TCPHeader*) (packet + 14 + (IH->HeaderLength * 4));
            printf("\nTCP Protocol\n");
            printf("Src Port : %d\n", ntohs(TCP-> sport));
            printf("Dst Port : %d\n", ntohs(TCP-> dport));
            printf("TCP Header len : %d\n", TH_OFF(TCP)*4);

            payload = (u_char *)(packet + 14 + (IH->HeaderLength *4) + (TH_OFF(TCP)*4));
            size_payload = ntohs(IH-> TotalLength) - ((IH->HeaderLength *4)+TH_OFF(TCP)*4);

            printf("\nTotalLength : %d\n", ntohs(IH-> TotalLength));
            printf("Payload : %d\n", size_payload);

            const u_char *ch = payload;

            if(size_payload >0) {
                printf("\npayload hexz Value\n");
                for(int j=0; j<size_payload; j++){
                    printf("%02x ", *ch);
                    if(j%16 == 15) printf("\n");
                    ch++;
                }
                printf("\n");
            }



        }


    }

    }
    /* And close the session */
    pcap_close(handle);
    return(0);
 }
