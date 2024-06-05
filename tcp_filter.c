#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>

SEC("filter")
int tcp_filter(struct __sk_buff *skb) {
    struct ethhdr *eth = bpf_hdr_pointer(skb, 0);
    struct iphdr *ip = (struct iphdr *)(eth + 1);
    struct tcphdr *tcp = (struct tcphdr *)(ip + 1);

    if (ip->protocol == IPPROTO_TCP && tcp->dest == htons(4040)) {
        return -1; // Drop packet
    }
    return 0; // Accept packet
}

char _license[] SEC("license") = "GPL";


//clang -O2 -target bpf -c tcp_filter.c -o tcp_filter.o
//sudo ip link set dev <your-interface> xdp obj tcp_filter.o verb
