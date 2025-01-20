#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <bpf/bpf_endian.h>

// Debug format strings
static const char fmt_eth[] = "Error: Packet too small for eth header\\n";
static const char fmt_proto[] = "Non-IPv4 packet: proto=0x%x\\n";
static const char fmt_ip[] = "Error: Packet too small for IP header\\n";
static const char fmt_count[] = "Error: Failed to lookup packet count\\n";
static const char fmt_redirect[] = "Error: Failed to lookup redirect interface\\n";
static const char fmt_success[] = "Redirecting to ifindex=%d, count=%llu\\n";

// Define map for packet counter per CPU
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} packet_count SEC(".maps");

// Define map for interface redirect targets
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 2);
    __type(key, __u32);
    __type(value, __u32);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} redirect_map SEC(".maps");

SEC("xdp")
int xdp_loadbalancer(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    // Ensure packet has enough data for ethernet header
    struct ethhdr *eth = data;
    if (data + sizeof(*eth) > data_end) {
        bpf_trace_printk(fmt_eth, sizeof(fmt_eth));
        return XDP_PASS;
    }

    // Only process IPv4 packets
    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        bpf_trace_printk(fmt_proto, sizeof(fmt_proto), bpf_ntohs(eth->h_proto));
        return XDP_PASS;
    }

    // Verify we can access IP header
    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)iph + sizeof(*iph) > data_end) {
        bpf_trace_printk(fmt_ip, sizeof(fmt_ip));
        return XDP_PASS;
    }

    // Update packet counter
    __u32 key = 0;
    __u64 *count = bpf_map_lookup_elem(&packet_count, &key);
    if (!count) {
        bpf_trace_printk(fmt_count, sizeof(fmt_count));
        return XDP_PASS;
    }

    // Increment counter
    __sync_fetch_and_add(count, 1);

    // Calculate target interface based on packet count
    __u32 target_idx = (*count) % 2;

    // Look up redirect interface index
    __u32 *if_idx = bpf_map_lookup_elem(&redirect_map, &target_idx);
    if (!if_idx) {
        bpf_trace_printk(fmt_redirect, sizeof(fmt_redirect));
        return XDP_PASS;
    }

    bpf_trace_printk(fmt_success, sizeof(fmt_success), *if_idx, *count);
    return bpf_redirect(*if_idx, 0);
}

char _license[] SEC("license") = "GPL";