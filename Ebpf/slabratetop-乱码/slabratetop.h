#pragma once

#define MAX_NAME_LEN 36

struct info_t {
    char name[MAX_NAME_LEN];
};

struct val_t {
    __u64 count;
    __u64 size;
};
/*
struct slab_t {
    unsigned long __page_flags;

#if defined(CONFIG_SLAB)
    struct kmem_cache *slab_cache;
    union {
        struct {
            struct list_head slab_list;
            void *freelist;
            void*s_mem;
        };
        struct rcu_head rcu_head;
    };
    unsigned int active;
#elif defined(CONFIG_SLUB)
    struct kmem_cache *slab_cache;
    union {
        struct {
            union  {
                struct list_head slab_list;
#ifdef CONFIG_SLUB_CPU_PARTIAL
                struct {
                    struct slab *next;
                    int slabs;
                };
#endif
            };
            void *freelist;
            union {
                unsigned long counters;
                struct {
                    unsigned inuse:16;
                    unsigned objects:15;
                    unsigned frozen:1;
                };
            };
        };
        struct rcu_head rcu_head;
    };
    unsigned int __unused;

#elif defined(CONFIG_SLOB)
    struct list_head slab_list;
    void *__unused_1;
    void *freelist;
    long units;
    unsigned int __unused_2;

#else
#error "Unexpected slab allocator configured"
#endif
    atomic_t __page_refcount;
#ifdef CNFIG_MEMCG
    unsigned long memcg_data;
#endif
};

#ifdef CONFIG_6BIT
typedef __uint128_t freelist_full_t;
#else
typedef u64 freelist_full_t;
#endif

typedef union {
    struct {
        void *freelist;
        unsigned long counter;
    };
    freelist_full_t full;
} freelist_aba_t;

#ifdef CONFIG_SLUB
#include <linux/slub_def.h>
#else
#include <linux/slab_def.h>
#endif*/

#define CACHE_NAME_LEN 32


/*struct slab {
    unsigned long __page_flags;

#if defined(CONFIG_SLAB)

    struct kmem_cache *slab_cache;
    union {
        struct {
            struct list_head slab_list;
            void *freelist;
            void *s_mem; 
        };
        struct rcu_head rcu_head;
    };
    unsigned int active;

#elif defined(CONFIG_SLUB)

    struct kmem_cache *slab_cache;
    union {
        struct {
            union {
                struct list_head slab_list;
#ifdef CONFIG_SLUB_CPU_PARTIAL
                struct {
                    struct slab *next;
                        int slabs;
                };
#endif
            };
            
            void *freelist; 
            union {
                unsigned long counters;
                struct {
                    unsigned inuse:16;
                    unsigned objects:15;
                    unsigned frozen:1;
                };
            };
        };
        struct rcu_head rcu_head;
    };
    unsigned int __unused;

#elif defined(CONFIG_SLOB)

    struct list_head slab_list;
    void *__unused_1;
    void *freelist;  
    long units;
    unsigned int __unused_2;

#else
#endif
    atomic_t __page_refcount;
#ifdef CONFIG_MEMCG
    unsigned long memcg_data;
#endif
};*/