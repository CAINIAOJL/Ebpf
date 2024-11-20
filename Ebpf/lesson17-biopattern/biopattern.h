#ifndef __BIOPATTERN_H__
#define __BIOPATTERN_H__

#define DISK_NAME_LEN 32

struct counter {
    __u64 last_sector;
    __u64 bytes;
    __u64 sequential; //顺序
    __u64 random;     //随机
};

#endif