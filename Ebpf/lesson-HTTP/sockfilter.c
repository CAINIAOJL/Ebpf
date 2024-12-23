/*#include <argp.h>
#include <arpa/inet.h>
#include <assert.h>
#include <bpf/libbpf.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <net/if.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <unistd.h>

#include "sockfilter.h"
#include "sockfilter.skel.h"*/

#include <argp.h>
#include <arpa/inet.h>
#include <assert.h>
#include <bpf/libbpf.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <net/if.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <unistd.h>
#include "sockfilter.h"
#include "sockfilter.skel.h"


static int open_raw_sock(const char *name) {
    struct sockaddr_ll sll; // 表示设备无关的物理层地址结构
    int sock;

    sock = socket(PF_PACKET, SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC, htons(ETH_P_ALL));
    if(sock < 0) {
        fprintf(stderr, "Failed to create raw socket: %s\n", strerror(errno));
        return -1;
    }

    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = if_nametoindex(name);
    sll.sll_protocol = htons(ETH_P_ALL);
    if(bind(sock, (struct sockaddr*)&sll, sizeof(sll)) < 0) {
        fprintf(stderr, "Failed to bind raw socket: %s\n", strerror(errno));
        close(sock);
        return -1;
    }
    return sock;
}

static inline void ltoa(uint32_t addr, char *dst)
{
	snprintf(dst, 16, "%u.%u.%u.%u", (addr >> 24) & 0xFF, (addr >> 16) & 0xFF,
		 (addr >> 8) & 0xFF, (addr & 0xFF));
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args) {
    return vfprintf(stderr, format, args);
}

static int handle_event(void *ctx, void *data, size_t size) {
    const struct so_event *e = data;
    char ifname[IF_NAMESIZE];
    char sstr[16] = {}, dstr[16] = {};

    if(e->pkt_type != PACKET_HOST) {
        return 0;
    }

    if(e->ip_proto < 0 || e->ip_proto >= IPPROTO_MAX) {
        return 0;
    }

    if(!if_indextoname(e->ifindex, ifname)) {
        return 0;
    }

    ltoa(ntohl(e->src_addr), sstr);
    ltoa(ntohl(e->dst_addr), dstr);
    //itoa(ntohl(e->src_addr), sstr);
	//itoa(ntohl(e->dst_addr), dstr);

    printf("%s:%d(src) -> %s:%d(dst)\n", sstr, ntohs(e->port16[0]), dstr, ntohs(e->port16[1]));
    printf("payload: %s\n", e->payload);

    return 0;
}

static volatile bool exiting = false;

static void sig_handler(int sig) {
    exiting = true;
}

int main(int argc, char** argv) {
    struct ring_buffer *rb = NULL;
    struct sockfilter *skel;
    int err, prog_fd, sock;
    //软件网络接口 ping 127.0.0.1
    const char *interface = "lo";

    libbpf_set_print(libbpf_print_fn);

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    skel = sockfilter__open_and_load();
    if(!skel) {
        fprintf(stderr, "Failed to open and load BPF skeleton\n");
        return 1;
    }

    rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
    if(!rb) {
        err = -1;
        fprintf(stderr, "Failed to create ring buffer\n");
        goto cleanup;
    }
    
    //create raw socket to receive packets from interface (lo = localhost)
    sock = open_raw_sock(interface);
    if(sock < 0) {
        err = -2;
        fprintf(stderr, "Failed to open raw socket\n");
        goto cleanup;
    }

    prog_fd = bpf_program__fd(skel->progs.socket_handler);
    if(setsockopt(sock, SOL_SOCKET, 50, &prog_fd, sizeof(prog_fd))) {
        err = -3;
        fprintf(stderr, "Failed to attach BPF program to socket\n");
        goto cleanup;
    }

    while(!exiting) {
        err = ring_buffer__poll(rb, 100);
        // ctrl + c to EINTR
        if(err == -EINTR) {
            err = 0;
            break;
        }

        if(err < 0) {
            fprintf(stderr, "Error polling ring buffer: %d\n", err);
            break;
        }

        sleep(1);
    }

cleanup:
    ring_buffer__free(rb);
    sockfilter__destroy(skel);
    close(sock);
    return -err;
}

