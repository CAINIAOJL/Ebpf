#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
//#define SEC(NAME) __attribute__((section(NAME), used))

struct {
    __uint(type, BPF_MAP_TYPE_STACK);
    __type(key, NULL);
    __type(value, sizeof(int));
    __uint(max_entries, 0);
    __type(map_flags, 0);
} stack_map SEC(".maps");


int do_sys_clone(void *ctx) {
    int i;
    for(i = 0; i < 5; i++) {
        bpf_map_update_elem(&stack_map, NULL, &i, BPF_ANY);
    }
    int value;
    for(i = 0; i < 5; i++) { 
        bpf_map_lookup_elem_and_delete(&stack_map, NULL, &value);
        printf("value read from the map: %d\n", value);
    }
}
