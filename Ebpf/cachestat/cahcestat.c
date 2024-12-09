#include <argp.h>
#include <errno.h>
#include <signal.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "cachestat.h"
#include "cachestat.skel.h"

#define warn(...) fprintf(stderr, __VA_ARGS__)

int mpa = 0;
int mbd = 0;
int apcl = 0;
int apd = 0;
int total = 0;
int misses = 0;
int hits = 0;


const char *argp_program_version = "slabratetop 1.0";
const char *argp_program_bug_address = "https://github.com/iovisor/bcc/tree/master/libbpf-tools";
const char argp_program_doc[] =
"#"
"# ./cachestat [-t timestamp] interval times\n"
"#  -t timestamp: optional timestamp in seconds since epoch\n"
"#  interval: interval in seconds to print the stats\n"
"#  times: number of times to print the stats\n"
"#\n"
"#  This tool uses in-kernel eBPF maps to track cache usage.\n"
"#\n"
"#  Example:\n"
"#  ./cachestat 1 10\n"
"#\n"
"#  This will print the cache stats every 1 second for 10 times.\n"
"#\n";

void get_meminfo(long *cached, long *buffer) {
    FILE *fp = fopen("/proc/meminfo", "r");
    if(fp == NULL) {
        perror("fopen");
        *cached = *buffer = 0;
        return;
    }
    char line[256];
    while(fgets(line, sizeof(line), fp)) {
        if(strncmp(line, "Cached:", 7) == 0) {
            sscanf(line, "Cached: %ld", cached);
        } else if(strncmp(line, "Buffers:", 8) == 0) { 
            sscanf(line, "Buffers: %ld", buffer);
        }
    }
    fclose(fp);
}

static struct env {
    time_t interval;
    bool timestamp;
    bool verbose;
    int times;
} env = {
	.interval = 99999999,
	.times = 99999999,
    .timestamp = false,
    .verbose = false,
};

static const struct argp_option opts[] = {
    {"verbose", 'v', NULL, 0, "verbose debug output"},
    {"rows", 't', NULL, 0, "show timestamp"},
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
        
        case 't':
            env.timestamp = true;
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

int print_map(struct bpf_map * counters) {
    __u32 total;
    struct key_t lookup_key, next_key;
    struct key_t entries[1024];
    memset(entries, 0, sizeof(entries));
    __u32 values[1024];
    int index = 0;
    memset(&lookup_key, 0, sizeof(lookup_key));
    memset(&next_key, 0, sizeof(next_key));
    int err, fd = bpf_map__fd(counters);

    while(!bpf_map_get_next_key(fd, &lookup_key, &next_key)) {
        if (index >= 1024) {
            break;
        }
        err = bpf_map_lookup_elem(fd, &next_key, &total);
        if(err < 0) {
            fprintf(stderr, "Failed to lookup map: %d\n", err);
            return -1;
        }
        lookup_key = next_key;
        entries[index] = next_key;
        values[index] = total;
        index++;
    }
    
    for (int i = 0; i < index; i++) {
        for (int j = i + 1; j < index; j++) {
            if (values[i] > values[j]) {
                struct key_t temp_value = entries[i];
                __u32 temp_key = values[i];
                entries[i] = entries[j];
                values[i] = values[j];
                entries[j] = temp_value;
                values[j] = temp_key;
            }
        }
    }

            // 计算统计数据
    for (int i = 0; i < index; i++) {
        int mpa = 0, mbd = 0, apcl = 0, apd = 0, total = 0, misses = 0, hits = 0;
        if (entries[i].nf == NF_APCL)
            apcl = values[i];
        else if (entries[i].nf == NF_MPA)
            mpa = values[i];
        else if (entries[i].nf == NF_MBD)
            mbd = values[i];
        else if (entries[i].nf == NF_APD)
            apd = values[i];

        total = mpa - mbd;
        misses = apcl - apd;
        if (misses < 0)
            misses = 0;
        if (total < 0)
            total = 0;
        hits = total - misses;

        if (hits < 0) {
            misses = total;
            hits = 0;
        }

        float ratio = total > 0 ? (float)hits / total : 0.0;

        // 获取内存信息
        long cached = 0, buffers = 0;
        get_meminfo(&cached, &buffers);

        printf("%8d %8d %8d %7.2f%% %12ld %10ld\n",
                    hits, misses, mbd, 100 * ratio, buffers / 1024, cached / 1024);
    }

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
    struct cachestat *skel;
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

    skel = cachestat__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    err = cachestat__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load BPF skeleton\n");
        goto cleanup;
    }

    skel->links.kprobe_filemap_add_folio = 
    bpf_program__attach_kprobe(skel->progs.kprobe_filemap_add_folio, false, "filemap_add_folio");

    if(!skel->links.kprobe_filemap_add_folio) {
        warn("(%s)Failed to attach kprobe: %d\n", "filemap_add_folio", -errno);
        return -1;
    }

    skel->links.kprobe_add_to_page_cache_lru = 
    bpf_program__attach_kprobe(skel->progs.kprobe_add_to_page_cache_lru, false, "add_to_page_cache_lru");

    if(!skel->links.kprobe_kmem_cache_alloc) {
        warn("(%s)Failed to attach kprobe: %d\n", "add_to_page_cache_lru", -errno);
        return -1;
    }
    
    skel->links.kprobe_folio_mark_accessed = 
    bpf_program__attach_kprobe(skel->progs.kprobe_folio_mark_accessed, false, "folio_mark_accessed");

    if(!skel->links.kprobe_folio_mark_accessed) {
        warn("(%s)Failed to attach kprobe: %d\n", "folio_mark_accessed", -errno);
        return -1;
    }

    skel->links.kprobe_mark_page_accessed = 
    bpf_program__attach_kprobe(skel->progs.kprobe_mark_page_accessed, false, "mark_page_accessed");

    if(!skel->links.kprobe_mark_page_accessed) {
        warn("(%s)Failed to attach kprobe: %d\n", "mark_page_accessed", -errno);
        return -1;
    }
    
    skel->links.kprobe_folio_account_dirtied = 
    bpf_program__attach_kprobe(skel->progs.kprobe_folio_account_dirtied, false, "folio_account_dirtied");

    if(!skel->links.kprobe_folio_account_dirtied) {
        warn("(%s)Failed to attach kprobe: %d\n", "folio_account_dirtied", -errno);
        return -1;
    }

    skel->links.kprobe_account_page_dirtied = 
    bpf_program__attach_kprobe(skel->progs.kprobe_account_page_dirtied, false, "account_page_dirtied");

    if(!skel->links.kprobe_account_page_dirtied) {
        warn("(%s)Failed to attach kprobe: %d\n", "account_page_dirtied", -errno);
        return -1;
    }

    skel->links.kprobe_mark_buffer_dirty = 
    bpf_program__attach_kprobe(skel->progs.kprobe_mark_buffer_dirty, false, "mark_buffer_dirty");

    if(!skel->links.kprobe_mark_buffer_dirty) {
        warn("(%s)Failed to attach kprobe: %d\n", "mark_buffer_dirty", -errno);
        return -1;
    }
    
    err = cachestat__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF programs: %s\n", strerror(-err));
        goto cleanup;
    }
    printf("Tracing... Hit Ctrl-C to exit (timeval %ld times %d).\n", env.interval, env.times);
    if(env.timestamp) {
        struct tm *tm;
        char ts[32];
        time_t t;

        time(&t);
        tm = localtime(&t);
        strftime(ts, sizeof(ts), "%H:%M:%S", tm);
        printf("%-9s ", ts);
    }

    long loop = 0;
    while (!exiting)
    {
        if (env.times > 0) {
            loop++;
            if (loop > env.times) {
                break;
            }
        }

        sleep(env.interval);

        err = print_map(skel->maps.counters);
        
        if(err) {
            break;
        }

        if(exiting) {
            break;
        }
    }

cleanup:
    cachestat__destroy(skel);
    return err != 0;

}