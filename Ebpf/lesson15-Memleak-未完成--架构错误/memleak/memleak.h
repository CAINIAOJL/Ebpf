#ifndef _MEMLEAK_H_
#define _MEMLEAK_H_

#define ALLOCS_MAX_ENTRIES 1000000
#define COMBINED_ALLOCS_MAX_ENTRIES 10240

/*单次分配内存的记录*/
struct alloc_info {
    __u64 size;            /* size of the allocation */
    __u64 timestamp_ns;    /* timestamp of the allocation */
    int stack_id;          /* stack id of the allocation */
};

/* 合并的分配内存的记录 */
union combined_alloc_info {
    struct {
        __u64 total_size : 40;
        __u64 number_of_allocs : 12;
    };
    __u64 bits;
};

#endif