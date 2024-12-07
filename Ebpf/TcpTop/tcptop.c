#include <argp.h>
#include <arpa/inet.h>
#include <errno.h>
#include <signal.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/utsname.h>
#include <time.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "tcptop.h"
#include "tcptop.skel.h"

#define warn(...) fprintf(stderr, __VA_ARGS__)

const char *argp_program_version = "tcptop 1.0";
const char *argp_program_bug_address = "https://github.com/iovisor/bcc/tree/master/libbpf-tools";
const char argp_program_doc[] =
" tcptop    Summarize TCP send/recv throughput by host."
"#           For Linux, uses BCC, eBPF. Embedded C."
"#"
"# USAGE: tcptop [-p PID] [-4 | -6]"
"#"
"# This uses dynamic tracing of kernel functions, and will need to be updated"
"# to match kernel changes";

struct env {
    bool verbose;
    pid_t pid;
    bool ipv4;
    bool ipv6;
} env = {
    .verbose = false,
    .pid = INVALID_PID,
    .ipv4 = false,
    .ipv6 = false,
};

static const struct argp_option opts[] = {
    {"verbose", 'v', NULL, 0, "verbose debug output"},
    {"ipv4", '4', NULL, 0, "trace IPV4 family only"},
    {"ipv6", '6', NULL, 0, "trace IPV6 family only"},
    {"pid", 'p', "PID", 0, "trace this PID only"},
    {},
};

static error_t parse_arg(int key, char* arg, struct argp_state* state) {
    static int pos_args;
    switch(key) {
        case '4':
            env.ipv4 = true;
            break;
    
        case '6':
            env.ipv6 = true;
            break;
        
        case 'v':
            env.verbose = true;
            break;
        
        case 'p':
            env.pid = strtol(arg, NULL, 10);
            if(env.pid < 0) {
                fprintf(stderr, "Invalid PID: %s\n", arg);
                argp_usage(state);
            }
            break;

        case ARGP_KEY_ARG: //没有 -x 选项
            argp_usage(state);
            break;
        
        default:
            return ARGP_ERR_UNKNOWN;
    }
    return 0;
}
//打印出libbpf的debug信息
static int libbpf_print_fn(enum libbpf_print_level level, const char* format, va_list args) {
    if(level == LIBBPF_DEBUG && !env.verbose) {
        return 0;
    }

    return vfprintf(stderr, format, args);
}

static volatile sig_atomic_t exiting = 0;

static void sig_int(int signo) {
    exiting = 1;
}

static bool set_up(void) {
    __sighandler_t err = signal(SIGINT, sig_int);
    if(err == SIG_ERR) {
        fprintf(stderr, "Can't set signal handler: %s\n", strerror(errno));
        return false;
    }

    err = signal(SIGTERM, sig_int);
    if (err == SIG_ERR) {
        fprintf(stderr, "Can't set signal handler: %s\n", strerror(errno));
        return false;
    }
    return true;
}

void print_ipv4_throughput(struct bpf_map *ipv4_send_bytes_map, struct bpf_map *ipv4_recv_bytes_map) {
    struct ipv4_key_t key, next_key;
    uint64_t value, send_value, recv_value;

    printf("%-7s %-12s %-21s %-21s %6s %6s\n", "PID", "COMM", "LADDR", "RADDR", "RX_KB(KB)", "TX_KB(KB)");

    while (bpf_map_get_next_key(ipv4_send_bytes_map, &key, &next_key) == 0) {
        if (bpf_map_lookup_elem(ipv4_send_bytes_map, &next_key, &send_value) < 0)
            send_value = 0;

        if (bpf_map_lookup_elem(ipv4_recv_bytes_map, &next_key, &recv_value) < 0)
            recv_value = 0;

        char laddr[16], raddr[16];
        inet_ntop(AF_INET, &next_key.saddr, laddr, sizeof(laddr));
        inet_ntop(AF_INET, &next_key.daddr, raddr, sizeof(raddr));

        printf("%-7d %-12.12s %-21s %-21s %6lu %6lu\n",
               next_key.pid, next_key.name, 
               laddr, raddr, 
               recv_value / 1024, send_value / 1024);

        // Delete the key from the map
        bpf_map_delete_elem(ipv4_send_bytes_map, &next_key);
        bpf_map_delete_elem(ipv4_recv_bytes_map, &next_key);

        key = next_key;
    }
}

void print_ipv6_throughput(struct bpf_map *ipv6_send_bytes_map, struct bpf_map *ipv6_recv_bytes_map) {
    struct ipv6_key_t key, next_key;
    uint64_t value, send_value, recv_value;

    printf("\n%-7s %-12s %-32s %-32s %6s %6s\n", "PID", "COMM", "LADDR6", "RADDR6", "RX_KB", "TX_KB");

    while (bpf_map_get_next_key(ipv6_send_bytes_map, &key, &next_key) == 0) {
        if (bpf_map_lookup_elem(ipv6_send_bytes_map, &next_key, &send_value) < 0)
            send_value = 0;

        if (bpf_map_lookup_elem(ipv6_recv_bytes_map, &next_key, &recv_value) < 0)
            recv_value = 0;

        char laddr6[40], raddr6[40];
        inet_ntop(AF_INET6, &next_key.saddr, laddr6, sizeof(laddr6));
        inet_ntop(AF_INET6, &next_key.daddr, raddr6, sizeof(raddr6));

        printf("%-7d %-12.12s %-32s %-32s %6lu %6lu\n",
               next_key.pid, next_key.name, 
               laddr6, raddr6, 
               recv_value / 1024, send_value / 1024);

        // Delete the key from the map
        bpf_map_delete_elem(ipv6_send_bytes_map, &next_key);
        bpf_map_delete_elem(ipv6_recv_bytes_map, &next_key);

        key = next_key;
    }
}


int main(int argc, char **argv) {
    struct tcptop *skel;
    int err;
    //LIBBPF_OPTS(bpf_object_open_opts, open_opts);
    static const struct argp argp = {
        .doc = argp_program_doc,
        .options = opts,
        .parser = parse_arg,
    };

    err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
    if(err) {
        fprintf(stderr, "Invalid option\n");
        return err;
    }

    libbpf_set_print(libbpf_print_fn);

    if(!set_up()) {
        fprintf(stderr, "Failed to set up signal handlers\n");
        return 1;
    }

    skel = tcptop__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    if (env.pid != INVALID_PID) {
        skel->rodata->target_pid = env.pid;
    }

    err = tcptop__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load BPF skeleton\n");
        goto cleanup;
    }

    //加载kprobe程序
    skel->links.kprobe_tcp_sendmsg_entry = 
    bpf_program__attach_kprobe(skel->progs.kprobe_tcp_sendmsg_entry, false, "tcp_sendmsg");

    if(!skel->links.kprobe_tcp_sendmsg_entry) {
        warn("(%s)Failed to attach kprobe: %d\n", "kprobe_tcp_sendmsg_entry", -errno);
        return -1;
    }

    skel->links.kprobe_tcp_sendmsg_return = 
    bpf_program__attach_kprobe(skel->progs.kprobe_tcp_sendmsg_return, true, "tcp_sendmsg");

    if(!skel->links.kprobe_tcp_sendmsg_return) {
        warn("(%s)Failed to attach kprobe: %d\n", "kprobe_tcp_sendmsg_return", -errno);
        return -1;
    }

    skel->links.kprobe_tcp_sendpage_entry = 
    bpf_program__attach_kprobe(skel->progs.kprobe_tcp_sendpage_entry, false, "tcp_sendapge");

    if(!skel->links.kprobe_tcp_sendpage_entry) {
        warn("(%s)Failed to attach kprobe: %d\n", "kprobe_tcp_sendpage_entry", -errno);
        return -1;
    }

    skel->links.kprobe_tcp_sendpage_return = 
    bpf_program__attach_kprobe(skel->progs.kprobe_tcp_sendpage_return, true, "tcp_sendapge");

    if(!skel->links.kprobe_tcp_sendpage_return) {
        warn("(%s)Failed to attach kprobe: %d\n", "kprobe_tcp_sendpage_return", -errno);
        return -1;
    }

    skel->links.kprobe_tcp_cleanup_rbuf_entry = 
    bpf_program__attach_kprobe(skel->progs.kprobe_tcp_cleanup_rbuf_entry, false, "tcp_cleanup_rbuf");

    if(!skel->links.kprobe_tcp_cleanup_rbuf_entry) {
        warn("(%s)Failed to attach kprobe: %d\n", "kprobe_tcp_cleanup_rbuf_entry", -errno);
        return -1;
    }

    err = tcptop__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF programs: %s\n", strerror(-err));
        goto cleanup;
    }
    printf("Tracing... Hit Ctrl-C to exit.\n");


    struct bpf_map *ipv4_send_bytes_map, *ipv4_recv_bytes_map;
    struct bpf_map *ipv6_send_bytes_map, *ipv6_recv_bytes_map;

    // Assume maps are loaded and available
    ipv4_send_bytes_map = bpf_object__find_map_by_name(obj, "ipv4_send_bytes");
    ipv4_recv_bytes_map = bpf_object__find_map_by_name(obj, "ipv4_recv_bytes");
    ipv6_send_bytes_map = bpf_object__find_map_by_name(obj, "ipv6_send_bytes");
    ipv6_recv_bytes_map = bpf_object__find_map_by_name(obj, "ipv6_recv_bytes");

    if (!ipv4_send_bytes_map || !ipv4_recv_bytes_map ||
        !ipv6_send_bytes_map || !ipv6_recv_bytes_map) {
        fprintf(stderr, "Failed to find one or more maps\n");
        return 1;
    }


    while (!exiting)
    {
        sleep(1);
        if(env.ipv4) {
            print_ipv4_throughput(ipv4_send_bytes_map, ipv4_recv_bytes_map);
        } else if(env.ipv6) {
            print_ipv6_throughput(ipv6_send_bytes_map, ipv6_recv_bytes_map);
        }

        if(!env.ipv4 && !env.ipv6) {
            print_ipv4_throughput(ipv4_send_bytes_map, ipv4_recv_bytes_map);
            print_ipv6_throughput(ipv6_send_bytes_map, ipv6_recv_bytes_map);
        }

        int errno = 0;
        if(errno == -EINTR) {
            err = 0;
            break;
        } 
    }

cleanup:
    tcptop__destroy(skel);
    return err != 0;

}