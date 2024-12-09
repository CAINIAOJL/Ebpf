#include <argp.h>
#include <errno.h>
#include <signal.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "slabratetop.h"
#include "slabratetop.skel.h"

#define warn(...) fprintf(stderr, __VA_ARGS__)

#define MAX_ROWS 1024
const char *argp_program_version = "slabratetop 1.0";
const char *argp_program_bug_address = "https://github.com/iovisor/bcc/tree/master/libbpf-tools";
const char argp_program_doc[] =
"#"
"# slabratetop  Summarize kmem_cache_alloc() calls."
"#              For Linux, uses BCC, eBPF."
"#"
"# USAGE: slabratetop [-h] [-r MAXROWS] [interval] [times]"
"#"
"# This uses in-kernel BPF maps to store cache summaries for efficiency."
"# Licensed under the Apache License, Version 2.0 license"
"#"
"# 15-Oct-2016   Brendan Gregg   Created this."
"# 23-Jan-2023   Rong Tao        Introduce kernel internal data structure and"
"#                               functions to temporarily solve problem for"
"#                               >=5.16(TODO: fix this workaround)";


//排序结构体
struct sorted_data {
    struct info_t key;
    struct val_t value;
};

//排序函数
int compare(const void *a, const void *b) {
    struct sorted_data *da = (struct sorted_data *)a;
    struct sorted_data *db = (struct sorted_data *)b;
    return da->value.count < db->value.count;
}

static struct env {
    time_t interval;
    int rows;
    bool verbose;
    int times;
} env = {
	.interval = 99999999,
	.times = 99999999,
    .rows = 15,
    .verbose = false,
};

static const struct argp_option opts[] = {
    {"verbose", 'v', NULL, 0, "verbose debug output"},
    {"rows", 'r', NULL, 0, "display this many rows (default 15)"},
    {},
};

static error_t parse_arg(int key, char* arg, struct argp_state* state) {
    static int pos_args;
    switch(key) {
        case 'h':
            argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
            break;
        
        case 'v':
            env.verbose = true;
            break;
        
        case 'r':
            env.rows = strtol(arg, NULL, 10);
            if(env.rows <= 0 || env.rows > MAX_ROWS) {
                fprintf(stderr, "rows is too long\n");
                argp_usage(state);
            }
            break;

        case ARGP_KEY_ARG: //没有 -x 选项
            errno = 0;
            if(pos_args == 0) {
                env.interval = strtol(arg, NULL, 10);
                if(errno) {
                    fprintf(stderr, "Invalid internal\n");
                    argp_usage(state);
                }
            } else if(pos_args == 1) {
                env.times = strtol(arg, NULL, 10);
                if(errno) {
                    fprintf(stderr, "Invalid times\n");
                    argp_usage(state);
                }
            } else {
                fprintf(stderr, "unrecognised argument: %s\n", arg);
                argp_usage(state);
            }
            pos_args++;
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

static int print_map(struct bpf_map *counts) {
    __u32 line = 0;
    struct info_t lookup_key;
    struct info_t next_key;
    struct val_t value;
    struct sorted_data *data_array;
    //分配内存
    data_array = malloc(sizeof(struct sorted_data) * env.rows);
    if(!data_array) {
        fprintf(stderr, "Failed to allocate memory\n");
        return -1;
    }

    int err, fd = bpf_map__fd(counts);

    printf("%-32s %6s %10s\n","CACHE", "ALLOCS", "BYTES");

    while(!bpf_map_get_next_key(fd, &lookup_key, &next_key)) {
        err = bpf_map_lookup_elem(fd, &next_key, &value);
        if(err < 0) {
            fprintf(stderr, "Failed to lookup map: %d\n", err);
            return -1;
        }

        data_array[line].key = next_key;
        data_array[line].value = value;

        lookup_key = next_key;
        line++;
        if (line >= env.rows) {
            break;
        }
    }

    qsort(data_array, env.rows, sizeof(struct sorted_data), compare);

    for(size_t i = 0; i < env.rows; i++) {
        printf("%-32s %6lld %10lld\n", data_array[i].key.name, data_array[i].value.count, data_array[i].value.size);
    }
    //释放内存
    free(data_array);
    
    //去除map
    memset(&lookup_key, 0, sizeof(lookup_key));
    while(!bpf_map_get_next_key(fd, &lookup_key, &next_key)) {
        err = bpf_map_delete_elem(fd, &next_key);
        if(err < 0) {
            fprintf(stderr, "Failed to delete map: %d\n", err);
            return -1;
        }
        lookup_key = next_key;
    }
    return 0;
}

int main(int argc, char **argv) {
    struct slabratetop *skel;
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

    skel = slabratetop__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    err = slabratetop__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load BPF skeleton\n");
        goto cleanup;
    }

    skel->links.kprobe_kmem_cache_alloc = 
    bpf_program__attach_kprobe(skel->progs.kprobe_kmem_cache_alloc, false, "kmem_cache_alloc");

    if(!skel->links.kprobe_kmem_cache_alloc) {
        warn("(%s)Failed to attach kprobe: %d\n", "kprobe_kmem_cache_alloc", -errno);
        return -1;
    }

    err = slabratetop__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF programs: %s\n", strerror(-err));
        goto cleanup;
    }
    printf("Tracing... Hit Ctrl-C to exit (timeval %ld times %d).\n", env.interval, env.times);

    while (!exiting)
    {
        sleep(env.interval);

        err = print_map(skel->maps.counts);
        if(err) {
            break;
        }

        if(exiting || --env.times == 0) {
            break;
        }
    }

cleanup:
    slabratetop__destroy(skel);
    return err != 0;

}