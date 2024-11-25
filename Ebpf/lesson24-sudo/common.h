#ifndef COMMON_H
#define COMMON_H

//set up ebpf tail call map
#define PROG_00 0
#define PROG_01 1
#define PROG_02 2


#define FILE_NAME_LEN 50
#define TEXT_LEN_MAX 20
#define max_payload_len 100
#define sudoers_len 13


#define TASK_CONN_LEN 16

struct event {
    int pid;
    char comm[TASK_CONN_LEN];
    bool success;
};

struct tr_file {
    char file_name[FILE_NAME_LEN];
    unsigned int filename_len;
};

struct tr_text {
    char text_name[TEXT_LEN_MAX];
    unsigned int text_len;
};

#endif