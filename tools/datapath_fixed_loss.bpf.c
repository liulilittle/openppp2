/* SPDX-License-Identifier: GPL-2.0 */
/*
 * TC direct-action carrier egress loss injector for strict datapath v3.
 *
 * This file intentionally has self-contained declarations so the contract's
 * exact clang invocation needs no host-specific include-directory flags.
 */
#ifndef PERIODIC_EVERY_N
#error "PERIODIC_EVERY_N must be defined"
#endif

#if PERIODIC_EVERY_N <= 0
#error "PERIODIC_EVERY_N must be positive"
#endif

#define SEC(NAME) __attribute__((section(NAME), used))
#define __uint(name, value) int (*name)[value]
#define __type(name, value) value *name

#define BPF_MAP_TYPE_ARRAY 2
#define BPF_FUNC_map_lookup_elem 1
#define TC_ACT_OK 0
#define TC_ACT_SHOT 2

typedef unsigned int __u32;
typedef unsigned long long __u64;

struct __sk_buff;

struct datapath_fixed_loss_counters {
    __u64 seen;
    __u64 dropped;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct datapath_fixed_loss_counters);
} counters SEC(".maps");

static void *(*bpf_map_lookup_elem)(const void *map, const void *key) =
    (void *)(long)BPF_FUNC_map_lookup_elem;

SEC("carrier_egress")
int datapath_fixed_loss(struct __sk_buff *skb) {
    const __u32 key = 0;
    struct datapath_fixed_loss_counters *value;
    __u64 seen;

    (void)skb;
    value = bpf_map_lookup_elem(&counters, &key);
    if (!value)
        return TC_ACT_OK;

    seen = __sync_fetch_and_add(&value->seen, 1) + 1;
    if (seen % PERIODIC_EVERY_N != 0)
        return TC_ACT_OK;

    __sync_fetch_and_add(&value->dropped, 1);
    return TC_ACT_SHOT;
}

char LICENSE[] SEC("license") = "GPL";
