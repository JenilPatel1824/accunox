#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>

#define PORT_MAP_SIZE 1

struct bpf_map_def SEC("maps") port_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(u32),
    .value_size = sizeof(u16),
    .max_entries = PORT_MAP_SIZE,
};

SEC("filter")
int tcp_filter(struct __sk_buff *skb) {
    u32 key = 0;
    u16 *port_ptr;
    u16 port;

    port_ptr = bpf_map_lookup_elem(&port_map, &key);
    if (!port_ptr)
        return 0; // Accept if port not found in map

    port = *port_ptr;

    struct ethhdr *eth = bpf_hdr_pointer(skb, 0);
    struct iphdr *ip = (struct iphdr *)(eth + 1);
    struct tcphdr *tcp = (struct tcphdr *)(ip + 1);

    if (ip->protocol == IPPROTO_TCP && tcp->dest == htons(port)) {
        return -1; // Drop packet
    }
    return 0; // Accept packet
}

char _license[] SEC("license") = "GPL";


//clang -O2 -target bpf -c tcp_filter.c -o tcp_filter.o
//sudo ip link set dev <your-interface> xdp obj tcp_filter.o verb

