#include <stdio.h>
#include <arpa/inet.h>
#include <inttypes.h>

#include "../libbpf/src/bpf.h"
#include "../libbpf/src/libbpf.h"

#define BASEDIR_MAPS "/sys/fs/bpf/tc/globals"

const char *info_map = BASEDIR_MAPS "/info_map";
const char *ip_map = BASEDIR_MAPS "/ip_map";

int info_map_fd, ip_map_fd;

struct packet_info
{
    uint32_t popIP;
    uint32_t gameIP;
    //uint32_t interalIP;
    uint16_t port;
};

int open_map(const char *name)
{
    // Initialize FD.
    int fd;

    // Get map objective.
    fd = bpf_obj_get(name);

    // Check map FD.
    if (fd < 0)
    {
        fprintf(stderr, "Error getting map. Map name => %s\n", name);

        return fd;
    }

    // Return FD.
    return fd;
}


int main()
{
    info_map_fd = open_map(info_map);
    ip_map_fd = open_map(ip_map);

    uint32_t key = 0;

    struct packet_info *pcktInfo;
    pcktInfo->popIP = inet_addr("10.50.0.3");
    //pcktInfo->interalIP = inet_addr("192.168.5.2");
    pcktInfo->gameIP = inet_addr("10.50.0.4");
    pcktInfo->port = htons(1337);

    bpf_map_update_elem(info_map_fd, &key, &pcktInfo, BPF_ANY);
    bpf_map_update_elem(ip_map_fd, &key, &pcktInfo->popIP, BPF_ANY);

    fprintf(stdout, "Updated BPF maps...\n");

    return 0;
}