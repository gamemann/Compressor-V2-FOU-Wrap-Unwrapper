#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/icmp.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/types.h>
#include <inttypes.h>

#ifndef __BPF__
#define __BPF__
#endif

#include "include/bpf_helpers.h"
#include "include/common.h"

// Map for Anycast/forwarding IP address.
struct bpf_elf_map SEC("maps") ip_map =
{
    .type = BPF_MAP_TYPE_ARRAY,
    .size_key = sizeof(uint32_t),
    .size_value = sizeof(uint32_t),
    .max_elem = 1,
    .pinning = PIN_GLOBAL_NS
};

SEC("unwrap")
int tc_unwrap(struct __sk_buff *skb)
{
    // Initialize SKB data and data end.
    void *data = (void *)(long)(skb->data);
    void *data_end = (void *)(long)(skb->data_end);

    // Initialize ethernet header.
    struct ethhdr *eth = (data);
    
    // Check if ethernet header is invalid (unlikely).
    if (unlikely(eth + 1 > (struct ethhdr *)data_end))
    {
        return TC_ACT_SHOT;
    }

    // Since we know this is a FOU-encap'ed packet already, let's remove the outer IP and UDP headers.
    if (bpf_skb_adjust_room(skb, -(int)(sizeof (struct iphdr) + sizeof(struct udphdr)), BPF_ADJ_ROOM_MAC, 0) != 0)
    {
        return TC_ACT_SHOT;
    }

    // Reinitialize data and data end.
    data = (void *)(long)(skb->data);
    data_end = (void *)(long)(skb->data_end);

    // Initiailize inner IP header.
    struct iphdr *ip = (data + sizeof(struct ethhdr));

    // Check inner IP header.
    if (unlikely(ip + 1 > (struct iphdr *)data_end))
    {
        return TC_ACT_SHOT;
    }

    // Initialize inner UDP header.
    struct udphdr *udp = (data + sizeof(struct udphdr) + (ip->ihl * 4));

    // Check inner UDP header.
    if (udp + 1 > (struct udphdr *)data_end)
    {
        return TC_ACT_SHOT;
    }

    // Get forwarding/Anycast address from map.
    uint32_t key = 0;
    uint32_t *addr = bpf_map_lookup_elem(&ip_map, &key);

    // Check if BPF map value is valid.
    if (!addr)
    {
        return TC_ACT_SHOT;
    }

    // Change inner IP header's source address to forwarding/Anycast address and save old address for checksum recalculation.
    uint32_t oldAddr = ip->saddr;
    ip->saddr = *addr;

    // Recalculate inner IP header's checksum.
    bpf_l3_csum_replace(skb, (sizeof (struct ethhdr) + offsetof(struct iphdr, check)), oldAddr, ip->saddr, sizeof(uint32_t));

    // Recalculate inner UDP header's checksum.
    bpf_l4_csum_replace(skb, (sizeof(struct ethhdr) + (ip->ihl * 4) + offsetof(struct udphdr, check)), oldAddr, ip->saddr, 0x10 | sizeof(uint32_t));

    return TC_ACT_OK;
}