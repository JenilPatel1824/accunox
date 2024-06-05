#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>

#define PORT_ALLOWED 4040

struct bpf_map_def SEC("maps") pid_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(u32),
    .value_size = sizeof(u32),
    .max_entries = 1024,
};

SEC("socket")
int socket_filter(struct __sk_buff *skb) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 *allowed_pid;

    allowed_pid = bpf_map_lookup_elem(&pid_map, &pid);
    if (!allowed_pid)
        return 0;

    struct ethhdr *eth = bpf_hdr_pointer(skb, 0);
    struct iphdr *ip = (struct iphdr *)(eth + 1);
    struct tcphdr *tcp = (struct tcphdr *)(ip + 1);

    if (ip->protocol == IPPROTO_TCP && ntohs(tcp->dest) != PORT_ALLOWED)
        return -1;

    return 0;
}

char _license[] SEC("license") = "GPL";
