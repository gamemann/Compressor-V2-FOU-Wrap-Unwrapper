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

//#define DEBUG

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
    // Get forwarding/Anycast address from map.
    uint32_t key = 0;
    uint32_t *addr = bpf_map_lookup_elem(&ip_map, &key);

    // Check if BPF map value is valid.
    if (!addr)
    {
        return TC_ACT_OK;
    }

    // Initialize SKB data and data end.
    void *data = (void *)(long)(skb->data);
    void *data_end = (void *)(long)(skb->data_end);

    // Initialize ethernet header.
    struct ethhdr *eth = data;
    
    // Check if ethernet header is invalid (unlikely).
    if (unlikely(eth + 1 > (struct ethhdr *)data_end))
    {
        return TC_ACT_SHOT;
    }

    // Since we know this is a FOU-encap'ed packet already, let's remove the outer IP and UDP headers.
    if (bpf_skb_adjust_room(skb, -(int)(sizeof(struct iphdr) + sizeof(struct udphdr)), BPF_ADJ_ROOM_MAC, 0) != 0)
    {
        return TC_ACT_SHOT;
    }

    // Reinitialize data and data end.
    data = (void *)(long)(skb->data);
    data_end = (void *)(long)(skb->data_end);

    // Initiailize inner IP header.
    struct iphdr *ip = data + sizeof(struct ethhdr);

    // Check inner IP header.
    if (unlikely(ip + 1 > (struct iphdr *)data_end))
    {
        return TC_ACT_SHOT;
    }

    // Only accept UDP and TCP protocols.
    if (unlikely(ip->protocol != IPPROTO_UDP && ip->protocol != IPPROTO_TCP))
    {
        return TC_ACT_SHOT;
    }

    // Change inner IP header's source address to forwarding/Anycast address and save old address for checksum recalculation.
    uint32_t oldAddr = ip->saddr;
    ip->saddr = *addr;

    // Recalculate inner IP header's checksum.
    bpf_l3_csum_replace(skb, sizeof (struct ethhdr) + offsetof(struct iphdr, check), oldAddr, ip->saddr, sizeof(ip->saddr));

    // Reinitialize data and data end.
    data = (void *)(long)(skb->data);
    data_end = (void *)(long)(skb->data_end);

    // Reinitialize ethernet header.
    eth = data;

    // Check ethernet header.
    if (eth + 1 > (struct ethhdr *)data_end)
    {
        return TC_ACT_SHOT;
    }

    // Reinitialize inner IP header.
    ip = data + sizeof(struct ethhdr);

    // Check inner IP header.
    if (ip + 1 > (struct iphdr *)data_end)
    {
        return TC_ACT_SHOT;
    }

    #ifdef DEBUG
        printk("Source host => %" PRIu32 ". Dest host => %" PRIu32 "\n", ip->saddr, ip->daddr);
    #endif

    uint8_t sMAC[ETH_ALEN];
    uint8_t dMAC[ETH_ALEN];

    // Store MAC addresses.
    bpf_memcpy(sMAC, eth->h_source, ETH_ALEN);
    bpf_memcpy(dMAC, eth->h_dest, ETH_ALEN);

    // Swap MAC addresses.
    bpf_skb_store_bytes(skb, offsetof(struct ethhdr, h_source), &dMAC, ETH_ALEN, 0);
    bpf_skb_store_bytes(skb, offsetof(struct ethhdr, h_dest), &sMAC, ETH_ALEN, 0);

    // Reinitialize data and data end.
    data = (void *)(long)(skb->data);
    data_end = (void *)(long)(skb->data_end);

    // Reinitialize ethernet header.
    eth = data;

    // Check ethernet header.
    if (eth + 1 > (struct ethhdr *)data_end)
    {
        return TC_ACT_SHOT;
    }

    // Reinitialize inner IP header.
    ip = data + sizeof(struct ethhdr);

    // Check inner IP header.
    if (ip + 1 > (struct iphdr *)data_end)
    {
        return TC_ACT_SHOT;
    }

    // Layer 4 header checksum recalculation.
    switch (ip->protocol)
    {
        case IPPROTO_UDP:
        {
            // Initialize inner UDP header.
            struct udphdr *udp = data + sizeof(struct ethhdr) + (ip->ihl * 4);

            // Check inner UDP header.
            if (udp + 1 > (struct udphdr *)data_end)
            {
                return TC_ACT_SHOT;
            }

            // Recalculate UDP header.
            bpf_l4_csum_replace(skb, sizeof(struct ethhdr) + (ip->ihl * 4) + offsetof(struct udphdr, check), oldAddr, ip->saddr, 0x10 | sizeof(ip->saddr));

            break;
        }

        case IPPROTO_TCP:
        {
            // Initialize inner TCP header.
            struct tcphdr *tcp = data + sizeof(struct ethhdr) + (ip->ihl * 4);

            // Check inner TCP header.
            if (tcp + 1 > (struct tcphdr *)data_end)
            {
                return TC_ACT_SHOT;
            }

            // Recalculate TCP header.
            bpf_l4_csum_replace(skb, sizeof(struct ethhdr) + (ip->ihl * 4) + offsetof(struct tcphdr, check), oldAddr, ip->saddr, 0x10 | sizeof(uint32_t));

            break;
        }
    }

    // Send the packet back out the TX path.
    bpf_clone_redirect(skb, skb->ifindex, 0);

    // Block the ingress packet.
    return TC_ACT_SHOT;
}

char __license[] SEC("license") = "GPL";