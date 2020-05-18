#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <inttypes.h>

#ifndef __BPF__
#define __BPF__
#endif

#define DEBUG

#include "include/bpf_helpers.h"
#include "include/common.h"
#include "include/csum.h"

struct bpf_elf_map SEC("maps") info_map =
{
    .type = BPF_MAP_TYPE_HASH,
    .size_key = sizeof(uint32_t),
    .size_value = sizeof(struct packet_info),
    .max_elem = MAX_FORWARDS,
    .pinning = PIN_GLOBAL_NS
};

SEC("wrap")
int tc_wrap(struct __sk_buff *skb)
{
    // Initialize data and data_end.
    void *data = (void *)(long)(skb->data);
    void *data_end = (void *)(long)(skb->data_end);

    // Initialize ethernet header.
    struct ethhdr *eth = (data);

    // Check ethernet header.
    if (unlikely(eth + 1 > (struct ethhdr *)data_end))
    {
        return TC_ACT_SHOT;
    }

    // Initialize outer IP header (will be inner IP header later).
    struct iphdr *ip = data + sizeof(struct ethhdr);

    // Check outer IP header.
    if (ip + 1 > (struct iphdr *)data_end)
    {
        return TC_ACT_SHOT;
    }

    // We only support inner TCP and UDP protocols.
    if (unlikely(ip->protocol != IPPROTO_UDP && ip->protocol != IPPROTO_TCP))
    {
        return TC_ACT_SHOT;
    }

    // Get forward map information.
    struct packet_info *info;
    
    info = bpf_map_lookup_elem(&info_map, &ip->daddr);

    // Check map. If map fails, just send packet through as normal since we haven't done anything with it yet.
    if (!info)
    {
        return TC_ACT_OK;
    }


    // Add outer IP and UDP headers.
    if (bpf_skb_adjust_room(skb, (int)(sizeof(struct iphdr) + sizeof(struct udphdr)), BPF_ADJ_ROOM_MAC, 0) != 0)
    {
        return TC_ACT_SHOT;
    }

    // Reinitialize data and data_end.
    data = (void *)(long)(skb->data);
    data_end = (void *)(long)(skb->data_end);

    // Reinitialize ethernet header.
    eth = data;

    // Check ethernet header.
    if (unlikely(eth + 1 > (struct ethhdr *)data_end))
    {
        return TC_ACT_SHOT;
    }

    // Store MAC addresses.
    uint8_t sMAC[ETH_ALEN];
    bpf_memcpy(sMAC, eth->h_source, ETH_ALEN);

    uint8_t dMAC[ETH_ALEN];
    bpf_memcpy(dMAC, eth->h_dest, ETH_ALEN);

    // Swap MAC addresses.
    bpf_skb_store_bytes(skb, offsetof(struct ethhdr, h_source), &dMAC, ETH_ALEN, 0);
    bpf_skb_store_bytes(skb, offsetof(struct ethhdr, h_dest), &sMAC, ETH_ALEN, 0);

    // Reinitialize data and data_end.
    data = (void *)(long)(skb->data);
    data_end = (void *)(long)(skb->data_end);

    // Reinitialize outer IP header.
    ip = data + sizeof(struct ethhdr);

    // Check outer IP header.
    if (unlikely(ip + 1 > (struct iphdr *)data_end))
    {
        return TC_ACT_SHOT;
    }

    // Initialize outer UDP header.
    struct udphdr *udp = data + sizeof(struct ethhdr) + sizeof(struct iphdr);

    // Check outer UDP header.
    if (udp + 1 > (struct udphdr *)data_end)
    {
        return TC_ACT_SHOT;
    }

    // Initialize inner IP header.
    struct iphdr *inner_ip = data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr);

    // Check inner IP header.
    if (unlikely(inner_ip + 1 > (struct iphdr *)data_end))
    {
        return TC_ACT_SHOT;
    }

    // Save inner IP destination address and replace with internal IP.
    uint32_t oldAddr = inner_ip->daddr;
    inner_ip->daddr = info->internalIP;

    // Fill out outer IP header.
    ip->ihl = 5;
    ip->version = 4;
    ip->id = 0;
    ip->frag_off = 0;
    ip->protocol = IPPROTO_UDP;
    ip->tos = 0x50;
    ip->ttl = 64;
    ip->saddr = info->popIP;
    ip->daddr = info->gameIP;
    ip->tot_len = htons(ntohs(inner_ip->tot_len) + sizeof(struct iphdr) + sizeof(struct udphdr));

    // Calculate outer IP header checksum.
    update_iph_checksum(ip);

    // Get payload size.
    uint16_t payloadSize = 0;

    // Recalculate inner layer 4 protocol.
    switch (inner_ip->protocol)
    {
        case IPPROTO_UDP:
        {
            // Initialize inner UDP header.
            struct udphdr *inner_udp = data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) + (inner_ip->ihl * 4);

            // Check inner UDP header.
            if (inner_udp + 1 > (struct udphdr *)data_end)
            {
                return TC_ACT_SHOT;
            }

            // Assign payload size.
            payloadSize = ntohs(inner_udp->len);

            // Recalculate inner UDP header checksum.
            bpf_l4_csum_replace(skb, sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) + (inner_ip->ihl * 4)  + offsetof(struct udphdr, check), oldAddr, inner_ip->daddr, 0x10 | sizeof(inner_ip->daddr));

            break;
        }

        case IPPROTO_TCP:
        {
            // Initialize inner TCP header.
            struct tcphdr *inner_tcp = data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) + (inner_ip->ihl);

            // Check inner TCP header.
            if (inner_tcp + 1 > (struct tcphdr *)data_end)
            {
                return TC_ACT_SHOT;
            }

            // Assign payload size.
            payloadSize = ntohs(inner_ip->tot_len) - (inner_tcp->doff * 4) - (inner_ip->ihl * 4);

            // Recalculate inner TCP header checksum.
            bpf_l4_csum_replace(skb, sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) + (inner_ip->ihl * 4)  + offsetof(struct tcphdr, check), oldAddr, inner_ip->daddr, 0x10 | sizeof(inner_ip->daddr));

            break;
        }
    }

    // Reinitialize data and data_end.
    data = (void *)(long)(skb->data);
    data_end = (void *)(long)(skb->data_end);

    // Reinitialize outer IP header.
    ip = data + sizeof(struct ethhdr);

    // Check outer IP header.
    if (ip + 1 > (struct iphdr *)data_end)
    {
        return TC_ACT_SHOT;
    }

    // Reinitialize outer UDP header.
    udp = data + sizeof(struct ethhdr) + sizeof(struct iphdr);

    // Check outer UDP header.
    if (udp + 1 > (struct udphdr *)data_end)
    {
        return TC_ACT_SHOT;
    }

    // Reinitialize inner IP header.
    inner_ip = data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr);

    // Check inner IP header.
    if (inner_ip + 1 > (struct iphdr *)data_end)
    {
        return TC_ACT_SHOT;
    }

    #ifdef DEBUG
        printk("Wrapping Program :: Source address => %" PRIu32 ". Destination address %" PRIu32 "...\n", inner_ip->saddr, inner_ip->daddr);
    #endif

    // Fill out outer UDP header.
    udp->len = htons(sizeof(struct udphdr) + payloadSize);
    udp->source = info->port;
    udp->dest = info->port;

    // Calculate outer UDP header checksum.
    udp->check = 0;

    // Send the packet back out the TX path.
    bpf_clone_redirect(skb, skb->ifindex, 0);

    // Block the ingress packet.
    return TC_ACT_SHOT;
}

char __license[] SEC("license") = "GPL";