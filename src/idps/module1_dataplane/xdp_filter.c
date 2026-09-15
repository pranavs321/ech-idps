// SPDX-License-Identifier: GPL-2.0
//
// Module 1 -- the data plane.
//
// An XDP program attached at the earliest point the kernel can run code on a
// received frame: before sk_buff allocation, before the network stack, before
// conntrack. A verdict here costs a hash lookup and returns XDP_DROP, so a
// condemned packet is discarded without ever being turned into a kernel
// object. That is the whole reason the split-plane design works: the control
// plane can take milliseconds to make a decision, because once made, acting on
// it costs essentially nothing.
//
// Two maps, deliberately separate:
//
//   blocked_ips     source-address bans. Wide, so entries here are only ever
//                   written when Module 5 established endpoint-intrinsic
//                   attribution (see module5_soar/policy.py).
//
//   blocked_tuples  connection-scoped bans. Narrow, used for the shared
//                   infrastructure case where banning an address would hit
//                   bystanders.
//
// Both are LRU_HASH rather than plain HASH. A plain hash that fills up starts
// rejecting inserts, which silently turns enforcement off at exactly the
// moment an attacker is spraying addresses at you. LRU degrades by forgetting
// the oldest entry instead, which is the failure mode you want.
//
// TTLs are enforced in-kernel by comparing against bpf_ktime_get_ns(), so an
// expired entry stops matching even if user space has not yet reaped it. Never
// rely on a userspace daemon to end a block on time; it may be dead.
//
// Build:  make -C src/idps/module1_dataplane
// Attach: sudo python3 -m idps.module1_dataplane.loader --iface eth0

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define MAX_BLOCKED_IPS    1048576
#define MAX_BLOCKED_TUPLES 1048576

struct block_entry {
    __u64 expires_ns;   // 0 means never
    __u64 hits;
    __u32 reason_code;
};

struct flow_tuple {
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_BLOCKED_IPS);
    __type(key, __u32);                 // IPv4 source address, network order
    __type(value, struct block_entry);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} blocked_ips SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_BLOCKED_TUPLES);
    __type(key, struct flow_tuple);
    __type(value, struct block_entry);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} blocked_tuples SEC(".maps");

// Counters, read by the dashboard. PERCPU avoids cache-line contention on the
// hot path -- a shared counter updated per packet would cost more than the
// lookup it is counting.
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 4);
    __type(key, __u32);
    __type(value, __u64);
} stats SEC(".maps");

#define STAT_SEEN      0
#define STAT_DROPPED   1
#define STAT_PASSED    2
#define STAT_EXPIRED   3

static __always_inline void bump(__u32 idx)
{
    __u64 *v = bpf_map_lookup_elem(&stats, &idx);
    if (v)
        __sync_fetch_and_add(v, 1);
}

static __always_inline int entry_is_live(struct block_entry *e, __u64 now)
{
    if (!e)
        return 0;
    if (e->expires_ns && now > e->expires_ns) {
        bump(STAT_EXPIRED);
        return 0;
    }
    __sync_fetch_and_add(&e->hits, 1);
    return 1;
}

SEC("xdp")
int idps_filter(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    __u64 now = bpf_ktime_get_ns();

    bump(STAT_SEEN);

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;   // IPv6 path: see note in loader.py

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    struct block_entry *e = bpf_map_lookup_elem(&blocked_ips, &ip->saddr);
    if (entry_is_live(e, now)) {
        bump(STAT_DROPPED);
        return XDP_DROP;
    }

    if (ip->protocol == IPPROTO_TCP) {
        // ip->ihl is in 32-bit words; bound it so the verifier can prove the
        // access stays inside the packet.
        __u32 ihl = ip->ihl * 4;
        if (ihl < sizeof(struct iphdr) || ihl > 60)
            return XDP_PASS;
        struct tcphdr *tcp = (void *)ip + ihl;
        if ((void *)(tcp + 1) > data_end)
            return XDP_PASS;

        struct flow_tuple t = {
            .saddr = ip->saddr,
            .daddr = ip->daddr,
            .sport = tcp->source,
            .dport = tcp->dest,
        };
        struct block_entry *te = bpf_map_lookup_elem(&blocked_tuples, &t);
        if (entry_is_live(te, now)) {
            bump(STAT_DROPPED);
            return XDP_DROP;
        }
    }

    bump(STAT_PASSED);
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
