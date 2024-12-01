#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <net/if.h>
#include <arpa/inet.h> 
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "xdp_tcpdump.skel.h"

static int handle_xdp_event(void *ctx, void* data, size_t data_sz) {
    if(data_sz < 20) {
        fprintf(stderr, "Received incomplete TCP header\n");
        return 0;
    }

    struct tcphdr {
        uint16_t source;
        uint16_t dest;
        uint32_t seq;
        uint32_t ack_seq;
        uint16_t res1:4,
                 doff:4,
                 fin:1,
                 syn:1,
                 rst:1,
                 psh:1,
                 ack:1,
                 urg:1,
                 ece:1,
                 cwr:1;
        uint16_t window;
        uint16_t check;
        uint16_t urg_ptr;
        // Options and padding may follow
    } __attribute__((packed));

    if(data_sz < sizeof(struct tcphdr)) {
        fprintf(stderr, "Received incomplete TCP header\n");
        return 0;
    }

    struct tcphdr *tcp = (struct tcphdr *)data;

    uint16_t source_port = ntohs(tcp->source);
    uint16_t dest_port = ntohs(tcp->dest);
    uint32_t seq = ntohl(tcp->seq);
    uint32_t ack_seq = ntohl(tcp->ack_seq);
    uint16_t window = ntohs(tcp->window);

    //8位flags
    uint8_t flags = 0;
    //00000000
    flags |= tcp->fin ? 0x01 : 0x00;
    flags |= tcp->syn ? 0x02 : 0x00;
    flags |= tcp->rst ? 0x04 : 0x00;
    flags |= tcp->psh ? 0x08 : 0x00;
    flags |= tcp->ack ? 0x10 : 0x00;
    flags |= tcp->urg ? 0x20 : 0x00;
    flags |= tcp->ece ? 0x40 : 0x00;
    flags |= tcp->cwr ? 0x80 : 0x00;

    printf("Captured TCP Header:\n");
    printf("  Source Port: %u\n", source_port);
    printf("  Destination Port: %u\n", dest_port);
    printf("  Sequence Number: %u\n", seq);
    printf("  Acknowledgment Number: %u\n", ack_seq);
    printf("  Data Offset: %u\n", tcp->doff);
    printf("  Flags: 0x%02x\n", flags);
    printf("  Window Size: %u\n", window);
    printf("\n");
    return 0;
}

int main(int argc, char ** argv) {
    struct xdp_tcpdump *skel;
    struct ring_buffer *rb = NULL;
    int err;
    //提供网口
    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s <ifname>\n", argv[0]);
        return 1;
    }

    const char *ifname = argv[1];
    int ifindex;
    ifindex = if_nametoindex(ifname);
    if(ifindex == 0) {
        fprintf(stderr, "Invalid interface name %s\n", ifname);
        return 1;
    }

    skel = xdp_tcpdump__open();
    if (!skel) {
        fprintf(stderr, "Failed to open and load BPF skeleton\n");
        return 1;
    }

    err = xdp_tcpdump__load(skel);
    if (err)
    {
        fprintf(stderr, "Failed to load and verify BPF skeleton: %d\n", err);
        goto cleanup;
    }

    err = xdp_tcpdump__attach(skel);
    if (err)
    {
        fprintf(stderr, "Failed to attach BPF skeleton: %d\n", err);
        goto cleanup;
    }

    skel->links.xdp_pass = bpf_program__attach_xdp(skel->progs.xdp_pass, ifindex);
    if(!skel->links.xdp_pass) {
        fprintf(stderr, "Failed to attach XDP program\n");
        err = -errno;
        goto cleanup;
    }

    printf("Successfully attached XDP program to interface %s\n", ifname);
    rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_xdp_event, NULL, NULL);
    if(!rb) {
        fprintf(stderr, "Failed to create ring buffer\n");
        err = -1;
        goto cleanup;
    }

    printf("Start polling ring buffer\n");

    while(1) {
        err = ring_buffer__poll(rb, -1);
        if(err = -EINTR) {
            continue;
        }
        if(err < 0) {
            fprintf(stderr, "Error polling ring buffer: %d\n", err);
            break;
        }
    }

cleanup:
    xdp_tcpdump__destroy(skel);
    ring_buffer__free(rb);

    return -err;
}
