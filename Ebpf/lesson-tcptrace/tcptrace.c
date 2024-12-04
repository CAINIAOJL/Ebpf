#include <argp.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <ctype.h>
#include <errno.h>
#include <linux/types.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "tcptrace.h"
#include "tcptrace.skel.h"

#define INVALID_PID -1
#define warn(...) fprintf(stderr, __VA_ARGS__)

const char *argp_program_version = "tcptrace 1.0";
const char *argp_program_bug_address = "https://github.com/iovisor/bcc/tree/master/libbpf-tools";
const char argp_program_doc[] =
"tcpv4tracer   Trace TCP connections."
"               For Linux, uses BCC, eBPF. Embedded C."
"\n"
//"USAGE: tcpv4tracer [-h] [-v] [-p PID] [-N NETNS] [-4 | -6]"
"USAGE: tcpv4tracer [-h] [-v] [-p PID] [-4 | -6]"
"You should generally try to avoid writing long scripts that measure multiple"
"functions and walk multiple kernel structures, as they will be a burden to"
"maintain as the kernel changes."
"The following code should be replaced, and simplified, when static TCP probes"
"exist.";

struct env {
    bool verbose;
    pid_t pid;
    bool ipv4;
    bool ipv6;
    bool timestamp;
    bool netns;
} env = {
    .verbose = false,
    .pid = INVALID_PID,
    .ipv4 = false,
    .ipv6 = false,
    .timestamp = false,
    .netns = false,
};

static const struct argp_option opts[] = {
    {"timestamp", 't', NULL, 0, "Include timestamp on output"},
    {"ipv4", '4', "IPV4", 0, "show IPv4 connections only"},
    {"verbose", 'v', NULL, 0, "verbose debug output"},
    {"ipv6", '6', "IPV6", 0, "show IPv6 connections only"},
    {"pid", 'p', "PID", 0, "trace this PID only"}
    {},
};

static error_t parse_arg(int key, char* arg, struct argp_state* state) {
    static int pos_args;
    switch(key) {
        case 'h':
            argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
            break;
    
        case 't':
            env.timestamp = true;
            break;
        
        case 'v':
            env.verbose = true;
            break;
        
        case 'n':
            env.netns = true;
            break;

        case '4':
            env.ipv4 = true;
            break;
        
        case '6':
            env.ipv6 = true;
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

char *get_func_name(char *version_type) {
    if (strcmp(version_type, "C") == 0) {
        return "connect";
    } else if (strcmp(version_type, "A") == 0) {
        return "accept";
    } else if (strcmp(version_type, "X") == 0) {
        return "close";
    }
    return "unkown";
}

static void print_ipv4_event(void *ctx, void *data, size_t data_sz) {
    struct tcp_ipv4_event_t *event = (struct tcp_ipv4_event_t *)data;
    char src[INET_ADDRSTRLEN];
    char dst[INET_ADDRSTRLEN];
    static __u64 start_ns = 0;
    if(env.timestamp) {
        if(start_ns == 0) {
            start_ns = event->ts_ns;
        }
        if(env.verbose) {
            printf("%-14ld", event.ts_ns - start_ns);
        } else {
            printf("%-9.3f", ((event.ts_ns - start_ns) / 1000000000.0));
        }
    }
    char *type_str;
    if(event->type == 1) {
        type_str = "C"; 
    } else if(event->type == 2) {
        type_str = "A";
    } else if(event->type == 3) {
        type_str = "X";
    } else {
        type_str = "U";
    }

    if(env.verbose) {
        printf("%-12s ", get_func_name(type_str));
    } else {
        printf("%-2s ", type_str);
    }

    print("%-6d %-16s %-2d %-16s %-16s %-6d %-6d", 
        event->pid, 
        event->comm, 
        event->ip, 
        inet_ntop(AF_INET, &event->saddr, src, INET_ADDRSTRLEN),
        inet_ntop(AF_INET, &event->daddr, dst, INET_ADDRSTRLEN),
        event->sport,
        event->dport);

    if(env.verbose && env.netns) {
        printf(" %-8d ", event->netns);
    } else {
        printf("\n");
    }
}

static void print_ipv6_event(void *ctx, void *data, size_t data_sz) {
    struct tcp_ipv6_event_t *event = (struct tcp_ipv6_event_t *)data;
    char src[INET6_ADDRSTRLEN];
    char dst[INET6_ADDRSTRLEN];
    static __u64 start_ns = 0;
    if(env.timestamp) {
        if(start_ns == 0) {
            start_ns = event->ts_ns;
        }
        if(env.verbose) {
            printf("%-14ld", event.ts_ns - start_ns);
        } else {
            printf("%-9.3f", ((event.ts_ns - start_ns) / 1000000000.0));
        }
    }
    char *type_str;
    if(event->type == 1) {
        type_str = "C"; 
    } else if(event->type == 2) {
        type_str = "A";
    } else if(event->type == 3) {
        type_str = "X";
    } else {
        type_str = "U";
    }

    if(env.verbose) {
        printf("%-12s ", get_func_name(type_str));
    } else {
        printf("%-2s ", type_str);
    }

    print("%-6d %-16s %-2d %-16s %-16s %-6d %-6d", 
        event->pid, 
        event->comm, 
        event->ip, 
        "[" + inet_ntop(AF_INET6, &event->saddr, src, INET_ADDRSTRLEN) + "]",
        "[" + inet_ntop(AF_INET6, &event->daddr, dst, INET_ADDRSTRLEN) + "]",
        event->sport,
        event->dport);

    if(env.verbose && env.netns) {
        printf(" %-8d ", event->netns);
    } else {
        printf("\n");
    }
}

int main(int argc, char** argv) {
    struct ring_buffer *rb_4 = NULL;
    struct ring_buffer *rb_6 = NULL;
    struct tcptrace_skel *skel;
    int err;
    LIBBPF_OPTS(bpf_object_open_opts, open_opts);
    static const struct argp argp = {
        .args_doc = argp_program_doc,
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

    err = tcptrace_skel__open(skel);
    if(err) {
        fprintf(stderr, "Failed to open BPF object: %s\n", strerror(-err));
        return 1;
    }

    err = tcptrace_skel__load(skel);
    if(err) {
        fprintf(stderr, "Failed to load BPF object: %s\n", strerror(-err));
        goto cleanup;
    }
    //内核函数
    if(env.ipv4) {
        obj->links.kprobe_tcp_v4_connect_entry = 
        bpf_program__attach_kprobe(obj->progs.kprobe_tcp_v4_connect_entry, false, "tcp_v4_connect");

        if(!obj->links.kprobe_tcp_v4_connect_entry) {
            warn("(%s)Failed to attach kprobe: %d\n", "kprobe_tcp_v4_connect_entry", -errno);
            return -1;
        }

        obj->links.krpobe_tcp_v4_connect_return = 
            bpf_program__attach_kprobe(obj->progs.krpobe_tcp_v4_connect_return, true, "tcp_v4_connect");

        if(!obj->links.krpobe_tcp_v4_connect_return) {
            warn("(%s)Failed to attach kprobe: %d\n", "krpobe_tcp_v4_connect_return", -errno);
            return -1;
        }
    } else if(env.ipv6) {
        obj->links.kprobe_tcp_v6_connect_entry = 
        bpf_program__attach_kprobe(obj->progs.kprobe_tcp_v6_connect_entry, false, "tcp_v6_connect");

        if(!obj->links.kprobe_tcp_v6_connect_entry) {
            warn("(%s)Failed to attach kprobe: %d\n", "kprobe_tcp_v6_connect_entry", -errno);
            return -1;
        }

        obj->links.kprobe_tcp_v6_connect_return = 
            bpf_program__attach_kprobe(obj->progs.kprobe_tcp_v6_connect_return, true, "tcp_v6_connect");

        if(!obj->links.kprobe_tcp_v6_connect_return) {
            warn("(%s)Failed to attach kprobe: %d\n", "kprobe_tcp_v6_connect_return", -errno);
            return -1;
        }
    } else {
        obj->links.kprobe_tcp_v4_connect_entry = 
        bpf_program__attach_kprobe(obj->progs.kprobe_tcp_v4_connect_entry, false, "tcp_v4_connect");

        if(!obj->links.kprobe_tcp_v4_connect_entry) {
            warn("(%s)Failed to attach kprobe: %d\n", "kprobe_tcp_v4_connect_entry", -errno);
            return -1;
        }

        obj->links.krpobe_tcp_v4_connect_return = 
            bpf_program__attach_kprobe(obj->progs.krpobe_tcp_v4_connect_return, true, "tcp_v4_connect");

        if(!obj->links.krpobe_tcp_v4_connect_return) {
            warn("(%s)Failed to attach kprobe: %d\n", "krpobe_tcp_v4_connect_return", -errno);
            return -1;
        }

        obj->links.kprobe_tcp_v6_connect_entry = 
        bpf_program__attach_kprobe(obj->progs.kprobe_tcp_v6_connect_entry, false, "tcp_v6_connect");

        if(!obj->links.kprobe_tcp_v6_connect_entry) {
            warn("(%s)Failed to attach kprobe: %d\n", "kprobe_tcp_v6_connect_entry", -errno);
            return -1;
        }

        obj->links.kprobe_tcp_v6_connect_return = 
            bpf_program__attach_kprobe(obj->progs.kprobe_tcp_v6_connect_return, true, "tcp_v6_connect");

        if(!obj->links.kprobe_tcp_v6_connect_return) {
            warn("(%s)Failed to attach kprobe: %d\n", "kprobe_tcp_v6_connect_return", -errno);
            return -1;
        }
    }

    obj->links.kprobe_tcp_set_state_entry = 
        bpf_program__attach_kprobe(obj->progs.kprobe_tcp_set_state_entry, false, "tcp_set_state");
    if(!obj->links.kprobe_tcp_set_state_entry) {    
        warn("(%s)Failed to attach kprobe: %d\n", "kprobe_tcp_set_state_entry", -errno);
        return -1;
    }

    obj->links.kprobe_tcp_close_entry = 
    bpf_program__attach_kprobe(obj->progs.kprobe_tcp_close_entry, false, "tcp_close");
    if(!obj->links.kprobe_tcp_close_entry) {    
        warn("(%s)Failed to attach kprobe: %d\n", "kprobe_tcp_close_entry", -errno);
        return -1;
    }

    obj->links.kprobe_inet_csk_accept_return = 
    bpf_program__attach_kprobe(obj->progs.kprobe_inet_csk_accept_return, true, "inet_csk_accept");
    if(!obj->links.kprobe_inet_csk_accept_return) {    
        warn("(%s)Failed to attach kprobe: %d\n", "kprobe_inet_csk_accept_return", -errno);
        return -1;
    }

   rb_4 = ring_buffer__new(bpf_map__fd(skel->maps.rb_ipv4), print_ipv4_event, NULL, NULL);
   rb_6 = ring_buffer__new(bpf_map__fd(skel->maps.rb_ipv6), print_ipv6_event, NULL, NULL);
   
    if(!rb_4 || !rb_6) {
        fprintf(stderr, "Failed to open ring buffer: %s\n", strerror(-errno));
        goto cleanup;
    }

    err = tcptrace_skel__attach(skel);
    if(err) {
        fprintf(stderr, "Failed to attach BPF programs: %s\n", strerror(-err));
        goto cleanup;
    }

    printf("TcpTracing .  Hit Ctrl-C to exit\n");

    while(!exiting) {
        int err1 = ring_buffer__poll(rb_4, 100);
        int err2 = ring_buffer__poll(rb_6, 100);
            /* Ctrl-C will cause -EINTR */
        if (err1 == -EINTR || err2 == -EINTR) {
            err = 0;
            break;
        }
        if (err1 < 0 || err2 < 0) {
            printf("Error polling perf buffer\n");
            break;
        }
    }

cleanup:
    tcptrace_skel__destroy(skel);
    ring_buffer__free(rb_4);
    ring_buffer__free(rb_6);

    return err < 0 ? -err : 0;

}