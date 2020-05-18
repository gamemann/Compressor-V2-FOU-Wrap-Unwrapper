#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <inttypes.h>

#include "../libbpf/src/bpf.h"
#include "../libbpf/src/libbpf.h"
#include "include/common.h"

#include <errno.h>
#include <error.h>
#include <string.h>

extern int errno;

#define BASEDIR_MAPS "/sys/fs/bpf/tc/globals"

const char *info_map = BASEDIR_MAPS "/info_map";

int info_map_fd;

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

    if (info_map_fd < 1)
    {
        printf("Error getting info map.\n");

        return 0;
    }

    uint32_t key = inet_addr("10.50.0.21");

    printf("Updating key %" PRIu32 "\n", key);

    struct packet_info *pcktInfo;
    pcktInfo->popIP = inet_addr("10.50.0.21");
    pcktInfo->internalIP = inet_addr("172.20.0.2");
    pcktInfo->gameIP = inet_addr("10.50.0.4");
    pcktInfo->port = htons(1337);
    
    printf("Using internal IP => %" PRIu32 "\n", pcktInfo->internalIP);

    if (bpf_map_update_elem(info_map_fd, &key, pcktInfo, BPF_ANY) != 0)
    {
        printf("Error updating map. Error num => %d. Error string => %s\n", errno, strerror(errno));
    }

    struct packet_info *newinfo = malloc(sizeof(struct packet_info));

    bpf_map_lookup_elem(info_map_fd, &key, newinfo);

    printf("Internal address from lookup => %" PRIu32 "\n", newinfo->internalIP);

    fprintf(stdout, "Updated BPF maps...\n");

    return 0;
}