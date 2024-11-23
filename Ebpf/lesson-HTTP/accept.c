#include <argp.h>
#include <arpa/inet.h>
#include <errno.h>
#include <signal.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/utsname.h>
#include <time.h>
#include <unistd.h>
#include <zlib.h>


#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <accept.h>
#define warn(...) fprintf(stderr, __VA_ARGS__)


/*static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args) {
    return vfprintf(stderr, format, args);
}*/

/*
struct socket_data_event_t {
    __u64 timestamp_ns;
    __u32 pid;
    //unsigned long long timestamp_ns;
    //unsigned int pid;
    int fd;
    bool is_connection;
    __u32 msg_size;
    //unsigned int msg_size;
    __u64 pos;
    //unsigned long long pos;
    char msg[MAX_MSG_SIZE];
};
*/

static volatile bool exiting = false;

static void handle_event(void *ctx, int cpu, void *data, __u32 data_sz) {
    struct socket_data_event_t *event = data;

    printf("timestamp_ns: %llu, pid: %u, fd: %d, is_connection: %d, msg_size: %u, pos: %llu, msg: %s\n",
         event->timestamp_ns, event->pid, event->fd, event->is_connection, 
         event->msg_size, event->pos, event->msg);
}
static void lost_event(void *ctx, int cpu, __u64 lost_cnt) {
    warn("lost %llu events on CPU %d\n", lost_cnt, cpu);
}

static void sig_handler(int sig) {
    exiting = true;
}


int main(int argc, char **argv) {
    struct accept *obj;
    struct perf_buffer *pb = NULL;
    int err;

    obj = accept__open();
    if (!obj) {
        warn("failed to open BPF object\n");
        return 1;
    }

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    while (1) {
        sleep(1);
    }

    return 0;           
}