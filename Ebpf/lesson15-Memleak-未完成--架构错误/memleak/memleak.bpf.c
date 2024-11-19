#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "maps.bpf.h"
#include "memleak.h"
#include "core.fixes.bpf.h"

const volatile size_t min_size = 0;
const volatile size_t max_size = -1;
const volatile size_t page_size = 4096;
const volatile __u64 sample_rate = 1;
const volatile bool trace_all = false;
const volatile __u64 stack_flags = 0;
const volatile bool wa_missing_free = false;

/**
 * @brief key: pid_t value: u64
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, pid_t);
    __type(value, u64); 
} sizes SEC(".maps");

/**
 * @brief key: address value: alloc_info
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, ALLOCS_MAX_ENTRIES);
    __type(key, u64);
    __type(value, struct alloc_info);
} allocs SEC(".maps");

/**
 * @brief key: stack_id value: combined_alloc_info
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, COMBINED_ALLOCS_MAX_ENTRIES);
    __type(key, u64);
    __type(value, union combined_alloc_info);
} combined_allocs SEC(".maps");

/**
 * @brief STACK_TRACE map to store stack traces: user->kernel kernel->user
 */
struct {
    __uint(type, BPF_MAP_TYPE_STACK_TRACE);
    __type(key, u32);
} stack_traces SEC(".maps");

/**
 * @brief key: pid value: memptr
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u64);
    __type(value, u64);
} memptrs SEC(".maps");

static union combined_alloc_info initial_cinfo;

static void update_statistics_add(u64 stack_id, u64 sz) {
    union combined_alloc_info *existing_cinfo;

    existing_cinfo = bpf_map_lookup_or_try_init(&combined_allocs, &stack_id, &initial_cinfo);
    if(!existing_cinfo) {
        return;
    }

    const union combined_alloc_info incremental_cinfo = {
        .total_size = sz,
        .number_of_allocs = 1
    };
    // 1: fetch first add then and return old value and old value + new value
    __sync_fetch_and_add(&existing_cinfo->bits, incremental_cinfo.bits);
}

static void update_statistics_del(u64 stack_id, u64 sz) {
    union combined_alloc_info *existing_cinfo;
    existing_cinfo = bpf_map_lookup_elem(&combined_allocs, &stack_id);
    if(!existing_cinfo) {
        bpf_printk("Failed to update combined_allocs\n");
        return ;
    }
    const union combined_alloc_info decremental_cinfo = {
        .number_of_allocs = 1,
        .total_size = sz
    };
    // 1: fetch first sub then and return old value and old value - new value
    __sync_fetch_and_sub(&existing_cinfo->bits, decremental_cinfo.bits);
}

/**
 * @brief generate alloc enter event  分配开始事件
 * @param size size of the allocation
 */
static int gen_alloc_enter(size_t size) {
    if (size < min_size || size > max_size) {
        return 0;
    }

/*
这一段代码的主要功能是在特定条件下控制程序的采样率，确保只处理特定频率的事件。下面是逐步的分解和详细解释：

条件检查：if(sample_rate > 1)
这一行代码首先检查变量 sample_rate 的值是否大于 1。如果 sample_rate 等于 1，表示每次分配都应该被记录，而大于 1 则意味着只需要记录一部分分配，这样可以减少处理的负担和数据的量。

采样逻辑：if(bpf_ktime_get_ns() % sample_rate != 0)
这一行使用 bpf_ktime_get_ns() 函数获取当前时间的纳秒级别的时间戳。然后，通过对 sample_rate 取模运算，检查当前时间是否可以被 sample_rate 整除。若结果不为零，则会返回 0，不执行后续的代码逻辑。

返回值：return 0;
如果上面的条件成立，即时间戳不能被 sample_rate 整除，程序就会返回 0，这表示此次分配的调用将被忽略，不进行进一步的处理。这样做的目的是确保只有在特定时间周期内的分配操作才会被采样和记录，从而降低了数据记录的频率，提升性能。

总结
这段代码的主要功能是实现采样率控制，通过采样率参数 sample_rate 来决定是否记录特定的分配事件。仅当满足特定的时间条件时，代码才会继续执行，反之则提前返回，减少不必要的处理和数据存储。这种技术常用于性能监控和资源管理，以保护系统免于过载。
*/

    if(sample_rate > 1) {
        if(bpf_ktime_get_ns() % sample_rate != 0) {
            return 0;
        }
    }

    const pid_t pid = bpf_get_current_pid_tgid() >> 32;
    bpf_map_update_elem(&sizes, &pid, &size, BPF_ANY);

    if(trace_all) {
        bpf_printk("pid_t = %d, alloc enter, size = %lu\n", pid, size);
    }
    return 0;
} 

/**
 * @brief generate alloc exit event 分配结束事件
 * @param ctx BPF context
 * @param size size of the allocation
 */
static int gen_alloc_exit2(void *ctx, u64 address) {
    const pid_t pid = bpf_get_current_pid_tgid() >> 32;

    const u64 *size = bpf_map_lookup_elem(&sizes, &pid);
    if(!size) {
        return 0; //missed alloc enter event;
    }    
    
    struct alloc_info info;
    __builtin_memset(&info, 0, sizeof(info));

    info.size = *size;
    bpf_map_delete_elem(&sizes, &pid);

    if(address != 0) {
        info.timestamp_ns = bpf_ktime_get_ns();

        info.stack_id = bpf_get_stackid(ctx, &stack_traces, stack_flags);

        bpf_map_update_elem(&allocs, &address, &info, BPF_ANY);

        update_statistics_add(info.stack_id, info.size);
    }

    if(trace_all) {
        bpf_printk("alloc exit, size = %lu, result = %lx\n", info.size, address);
    }

    return 0;
}

static int gen_alloc_exit(struct pt_regs *ctx) {
    return gen_alloc_exit2(ctx, PT_REGS_RC(ctx));
}

static int gen_free_enter(const void* address) {
    const u64 addr = (u64)address;

    const struct alloc_info *info = bpf_map_lookup_elem(&allocs, &addr);
    if(!info) {
        return 0; 
    }

    bpf_map_delete_elem(&allocs, &addr);

    update_statistics_del(info->stack_id, info->size);

    if(trace_all) {
        bpf_printk("free enter, size = %lu, address = %lx\n", info->size, address);
    }
    return 0;
}

SEC("uprobe")
int BPF_KPROBE(malloc_enter, size_t size) {
    return gen_alloc_enter(size);
}

SEC("uretprobe")
int BPF_KPROBE(malloc_exit) {
    return gen_alloc_exit(ctx);
}

SEC("uprobe")
int BPF_KPROBE(free_enter, void *address) {
    return gen_free_enter(address);
}

//calloc
SEC("uprobe")
int BPF_KPROBE(calloc_entet, size_t memb, size_t size) {
    return gen_alloc_enter(memb * size);
}

SEC("uretprobe")
int BPF_KPROBE(calloc_exit) {
    return gen_alloc_exit(ctx);
}

SEC("uprobe")
int BPF_KPROBE(realloc_enter, void *ptr, size_t size) {
    gen_free_enter(ptr);
    return gen_alloc_enter(size);
}

SEC("uretprobe") 
int BPF_KPROBE(realloc_exit) {
    return gen_alloc_exit(ctx);
}

SEC("uprobe")
int BPF_KPROBE(mmap_enter, void *address, size_t size) {
    return gen_alloc_enter(size);
}

SEC("uretprobe")
int BPF_KPROBE(mmap_exit) {
    return gen_alloc_exit(ctx);
}

SEC("uprobe")
int BPF_KPROBE(munmap_enter, void *address) {
    return gen_free_enter(address);
}

SEC("uprobe")
int BPF_KPROBE(posix_memalign_enter, void **memptr, size_t alignment, size_t size) {
    const u64 memptr = (u64)(size_t)memptr;
    const u64 pid = bpf_get_current_pid_tgid() >> 32;
    bpf_map_update_elem(&memptrs, &pid, &memptr, BPF_ANY);

    return gen_alloc_enter(size);
}

SEC("uretprobe")
int BPF_KPROBE(posix_memalign_exit) {
    const u64 pid = bpf_get_current_pid_tgid() >> 32;
    u64 *memptr64 = bpf_map_lookup_elem(&memptrs, &pid);
    void *addr;

    if(!memptr64) {
        return 0;
    }

    bpf_map_delete_elem(&memptrs, &pid);

    if(bpf_probe_read_user(&addr, sizeof(void*), (void*)(size_t)*memptr64)) {
        return 0;
    }

    const u64 addr64 = (u64)(size_t)addr;

    return gen_alloc_exit2(ctx, addr64);
}

SEC("uprobe")
int BPF_KPROBE(aligned_alloc_enter, size_t alignment, size_t size) {
    return gen_alloc_enter(size);
}

SEC("uretprobe")
int BPF_KPROBE(aligned_alloc_exit) {
    return gen_alloc_exit(ctx);
}

SEC("uprobe")
int BPF_KPROBE(valloc_enter, size_t size) {
    return gen_alloc_enter(size);
}

SEC("uretprobe")
int BPF_KPROBE(valloc_exit) {
    return gen_alloc_exit(ctx);
}

SEC("uprobe")
int BPF_KPROBE(memalign_enter, size_t alignment, size_t size) {
    return gen_alloc_enter(size);
}

SEC("uretprobe")
int BPF_KPROBE(memalign_exit) {
    return gen_alloc_exit(ctx);
}

SEC("uprobe")
int BPF_KPROBE(pvalloc_enter, size_t size) {
    return gen_alloc_enter(size);
}

SEC("uretprobe")
int BPF_KPROBE(pvalloc_exit) {
    return gen_alloc_exit(ctx);
}

/**
 * commit 11e9734bcb6a("mm/slab_common: unify NUMA and UMA version of
 * tracepoints") drops kmem_alloc event class, rename kmem_alloc_node to
 * kmem_alloc, so `trace_event_raw_kmem_alloc_node` is not existed any more.
 * see:
 *    https://github.com/torvalds/linux/commit/11e9734bcb6a
 */
struct trace_event_raw_kmem_alloc_node___x {
	const void *ptr;
	size_t bytes_alloc;
} __attribute__((preserve_access_index));

static __always_inline bool has_kmem_alloc_node(void)
{
	if (bpf_core_type_exists(struct trace_event_raw_kmem_alloc_node___x))
		return true;
	return false;
}


/**
 * commit 2c1d697fb8ba("mm/slab_common: drop kmem_alloc & avoid dereferencing
 * fields when not using") drops kmem_alloc event class. As a result,
 * `trace_event_raw_kmem_alloc` is removed, `trace_event_raw_kmalloc` and
 * `trace_event_raw_kmem_cache_alloc` are added.
 * see:
 *    https://github.com/torvalds/linux/commit/2c1d697fb8ba
 */
struct trace_event_raw_kmem_alloc___x {
	const void *ptr;
	size_t bytes_alloc;
} __attribute__((preserve_access_index));

struct trace_event_raw_kmalloc___x {
	const void *ptr;
	size_t bytes_alloc;
} __attribute__((preserve_access_index));

struct trace_event_raw_kmem_cache_alloc___x {
	const void *ptr;
	size_t bytes_alloc;
} __attribute__((preserve_access_index));

static __always_inline bool has_kmem_alloc(void)
{
	if (bpf_core_type_exists(struct trace_event_raw_kmem_alloc___x))
		return true;
	return false;
}


SEC("tracepoint/kmem/kmalloc")
int memleak_kmlloc(void *ctx) {
    const void *ptr;
	size_t bytes_alloc;

	if (has_kmem_alloc()) {
		struct trace_event_raw_kmem_alloc___x *args = ctx;
		ptr = BPF_CORE_READ(args, ptr);
		bytes_alloc = BPF_CORE_READ(args, bytes_alloc);
	} else {
		struct trace_event_raw_kmalloc___x *args = ctx;
		ptr = BPF_CORE_READ(args, ptr);
		bytes_alloc = BPF_CORE_READ(args, bytes_alloc);
	}

	if (wa_missing_free)
		gen_free_enter(ptr);

	gen_alloc_enter(bytes_alloc);

	return gen_alloc_exit2(ctx, (u64)ptr);
}

SEC("tracepoint/kmem/kmalloc_node")
int memleak__kmalloc_node(void *ctx)
{
	const void *ptr;
	size_t bytes_alloc;

	if (has_kmem_alloc_node()) {
		struct trace_event_raw_kmem_alloc_node___x *args = ctx;
		ptr = BPF_CORE_READ(args, ptr);
		bytes_alloc = BPF_CORE_READ(args, bytes_alloc);

		if (wa_missing_free)
			gen_free_enter(ptr);

		gen_alloc_enter( bytes_alloc);

		return gen_alloc_exit2(ctx, (u64)ptr);
	} else {
		/* tracepoint is disabled if not exist, avoid compile warning */
		return 0;
	}
}

SEC("tracepoint/kmem/kfree")
int memleak__kfree(void *ctx)
{
	const void *ptr;

	if (has_kfree()) {
		struct trace_event_raw_kfree___x *args = ctx;
		ptr = BPF_CORE_READ(args, ptr);
	} else {
		struct trace_event_raw_kmem_free___x *args = ctx;
		ptr = BPF_CORE_READ(args, ptr);
	}

	return gen_free_enter(ptr);
}

SEC("tracepoint/kmem/kmem_cache_alloc")
int memleak__kmem_cache_alloc(void *ctx)
{
	const void *ptr;
	size_t bytes_alloc;

	if (has_kmem_alloc()) {
		struct trace_event_raw_kmem_alloc___x *args = ctx;
		ptr = BPF_CORE_READ(args, ptr);
		bytes_alloc = BPF_CORE_READ(args, bytes_alloc);
	} else {
		struct trace_event_raw_kmem_cache_alloc___x *args = ctx;
		ptr = BPF_CORE_READ(args, ptr);
		bytes_alloc = BPF_CORE_READ(args, bytes_alloc);
	}

	if (wa_missing_free)
		gen_free_enter(ptr);

	gen_alloc_enter(bytes_alloc);

	return gen_alloc_exit2(ctx, (u64)ptr);
}

SEC("tracepoint/kmem/kmem_cache_alloc_node")
int memleak__kmem_cache_alloc_node(void *ctx)
{
	const void *ptr;
	size_t bytes_alloc;

	if (has_kmem_alloc_node()) {
		struct trace_event_raw_kmem_alloc_node___x *args = ctx;
		ptr = BPF_CORE_READ(args, ptr);
		bytes_alloc = BPF_CORE_READ(args, bytes_alloc);

		if (wa_missing_free)
			gen_free_enter(ptr);

		gen_alloc_enter(bytes_alloc);

		return gen_alloc_exit2(ctx, (u64)ptr);
	} else {
		/* tracepoint is disabled if not exist, avoid compile warning */
		return 0;
	}
}

SEC("tracepoint/kmem/kmem_cache_free")
int memleak__kmem_cache_free(void *ctx)
{
	const void *ptr;

	if (has_kmem_cache_free()) {
		struct trace_event_raw_kmem_cache_free___x *args = ctx;
		ptr = BPF_CORE_READ(args, ptr);
	} else {
		struct trace_event_raw_kmem_free___x *args = ctx;
		ptr = BPF_CORE_READ(args, ptr);
	}

	return gen_free_enter(ptr);
}

SEC("tracepoint/kmem/mm_page_alloc")
int memleak__mm_page_alloc(struct trace_event_raw_mm_page_alloc *ctx)
{
	gen_alloc_enter(page_size << ctx->order);

	return gen_alloc_exit2(ctx, ctx->pfn);
}

SEC("tracepoint/kmem/mm_page_free")
int memleak__mm_page_free(struct trace_event_raw_mm_page_free *ctx)
{
	return gen_free_enter((void *)ctx->pfn);
}

SEC("tracepoint/percpu/percpu_alloc_percpu")
int memleak__percpu_alloc_percpu(struct trace_event_raw_percpu_alloc_percpu *ctx)
{
	gen_alloc_enter(ctx->bytes_alloc);

	return gen_alloc_exit2(ctx, (u64)(ctx->ptr));
}

SEC("tracepoint/percpu/percpu_free_percpu")
int memleak__percpu_free_percpu(struct trace_event_raw_percpu_free_percpu *ctx)
{
	return gen_free_enter(ctx->ptr);
}

char LICENSE[] SEC("license") = "GPL";