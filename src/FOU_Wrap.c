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

#include "include/bpf_helpers.h"
#include "include/common.h"
#include "include/csum.h"

struct packet_info
{
    uint32_t popIP;
    uint32_t gameIP;
    uint16_t port;
};

struct bpf_elf_map SEC("maps") info_map =
{
    .type = BPF_MAP_TYPE_ARRAY,
    .size_key = sizeof(uint32_t),
    .size_value = sizeof(struct packet_info),
    .max_elem = 1,
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

    // Add outer IP and UDP headers.
    if (bpf_skb_adjust_room(skb, (int)(sizeof (struct iphdr) + sizeof(struct udphdr)), BPF_ADJ_ROOM_MAC, 0) != 0)
    {
        return TC_ACT_SHOT;
    }

    // Reinitialize data and data_end.
    data = (void *)(long)(skb->data);
    data_end = (void *)(long)(skb->data_end);

    // Initialize outer IP header.
    struct iphdr *ip = (data + sizeof(struct ethhdr));

    // Check outer IP header.
    if (unlikely(ip + 1 > (struct iphdr *)data_end))
    {
        return TC_ACT_SHOT;
    }

    // Initialize outer UDP header.
    struct udphdr *udp = (data + sizeof(struct ethhdr) + sizeof(struct iphdr));

    // Check outer UDP header.
    if (udp + 1 > (struct udphdr *)data_end)
    {
        return TC_ACT_SHOT;
    }

    // Initialize inner IP header.
    struct iphdr *inner_ip = (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr));

    // Check inner IP header.
    if (unlikely(inner_ip + 1 > (struct iphdr *)data_end))
    {
        return TC_ACT_SHOT;
    }

    // Make sure we only have UDP and TCP packets.
    if (unlikely(inner_ip->protocol != IPPROTO_UDP && inner_ip->protocol != IPPROTO_TCP))
    {
        return TC_ACT_SHOT;
    }

    // Get source port of either UDP or TCP header.
    uint16_t sPort;

    switch (inner_ip->protocol)
    {
        case IPPROTO_UDP:
        {
            // Initialize inner UDP header.
            struct udphdr *inner_udp = (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) + (inner_ip->ihl * 4));

            // Check inner UDP header.
            if (inner_udp + 1 > (struct udphdr *)data_end)
            {
                return TC_ACT_SHOT;
            }

            // Assign source port to sPort.
            sPort = inner_udp->source;

            break;
        }

        case IPPROTO_TCP:
        {
            // Initialize inner TCP header.
            struct tcphdr *inner_tcp = (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) + (inner_ip->ihl));

            // Check inner TCP header.
            if (inner_tcp + 1 > (struct tcphdr *)data_end)
            {
                return TC_ACT_SHOT;
            }

            // Assign source port to sPort.
            sPort = inner_tcp->source;

            break;
        }
    }

    // Get map that includes necessary information.
    uint32_t key = 0;
    struct packet_info *info;

    info = bpf_map_lookup_elem(&info_map, &key);

    // Check map's value.
    if (!info)
    {
        return TC_ACT_SHOT;
    }

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

    // Fill out outer UDP header.
    udp->len = htons(sizeof(struct udphdr));
    udp->source = sPort;
    udp->dest = info->port;

    // Calculate outer UDP header checksum.
    udp->check = 0;

    return TC_ACT_OK;
}