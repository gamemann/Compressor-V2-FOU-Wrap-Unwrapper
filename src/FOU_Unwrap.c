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

#define PIN_GLOBAL_NS 2

struct bpf_elf_map 
{
    __u32 type;
    __u32 size_key;
    __u32 size_value;
    __u32 max_elem;
    __u32 flags;
    __u32 id;
    __u32 pinning;
    __u32 inner_id;
    __u32 inner_idx;
};

// MAC map for gateway interface's MAC address. The program only worked for me if I had the Ethernet header's destination MAC address set to the gateway.
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

    return TC_ACT_OK;
}