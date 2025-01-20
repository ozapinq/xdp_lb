#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <net/if.h>
#include <linux/bpf.h>

// Helper function to wrap bpf syscall
static inline int sys_bpf(enum bpf_cmd cmd, union bpf_attr *attr, unsigned int size)
{
    return syscall(__NR_bpf, cmd, attr, size);
}

// Helper function to open bpf object
static int bpf_obj_get(const char *pathname)
{
    union bpf_attr attr = {
        .pathname = (__u64)pathname,
        .file_flags = 0,
    };
    return sys_bpf(BPF_OBJ_GET, &attr, sizeof(attr));
}

// Helper function to update map
static int bpf_map_update_elem(int fd, const void *key, const void *value, __u64 flags)
{
    union bpf_attr attr = {
        .map_fd = fd,
        .key = (__u64)key,
        .value = (__u64)value,
        .flags = flags,
    };
    return sys_bpf(BPF_MAP_UPDATE_ELEM, &attr, sizeof(attr));
}

int main(int argc, char **argv) {
    if (argc != 4) {
        printf("Usage: %s <bpf-map> <if1_name> <if2_name>\n", argv[0]);
        printf("Example: %s /sys/fs/bpf/redirect_map eth1 eth2\n", argv[0]);
        return 1;
    }

    // Open the BPF map
    int map_fd = bpf_obj_get(argv[1]);
    if (map_fd < 0) {
        fprintf(stderr, "Error opening map: %s\n", strerror(errno));
        return 1;
    }

    // Get interface indices
    unsigned int if1_index = if_nametoindex(argv[2]);
    unsigned int if2_index = if_nametoindex(argv[3]);

    if (if1_index == 0 || if2_index == 0) {
        fprintf(stderr, "Error getting interface index\n");
        return 1;
    }

    // Update the map
    __u32 key = 0;
    int ret = bpf_map_update_elem(map_fd, &key, &if1_index, BPF_ANY);
    if (ret < 0) {
        fprintf(stderr, "Error updating map for if1: %s\n", strerror(errno));
        return 1;
    }

    key = 1;
    ret = bpf_map_update_elem(map_fd, &key, &if2_index, BPF_ANY);
    if (ret < 0) {
        fprintf(stderr, "Error updating map for if2: %s\n", strerror(errno));
        return 1;
    }

    printf("Successfully configured interfaces:\n");
    printf("Index 0 -> %s (ifindex %u)\n", argv[2], if1_index);
    printf("Index 1 -> %s (ifindex %u)\n", argv[3], if2_index);

    return 0;
}