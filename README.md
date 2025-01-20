# XDP Load Balancer

A simple XDP-based load balancer that distributes IPv4 traffic between two network interfaces using round-robin approach based on packet count.

## Prerequisites

Install required dependencies on Fedora:
```bash
sudo dnf install -y \
    clang \
    llvm \
    make \
    gcc \
    libbpf-devel \
    elfutils-libelf-devel \
    bpftool \
    kernel-headers
```

## Building

Build the programs:
```bash
make
```

This will create two files:
- `xdp_loadbalancer.o` - The compiled XDP program
- `xdp_config` - The configuration utility

## Usage

1. Create the BPF filesystem mount point (if it doesn't exist):
```bash
sudo mount -t bpf bpf /sys/fs/bpf/
```

2. Load the XDP program on your input interface (e.g., eth1):
```bash
sudo ip link set dev eth1 xdp obj xdp_loadbalancer.o sec xdp
```

3. Configure target interfaces for load balancing (e.g., eth2 and eth3):
```bash
sudo ./xdp_config /sys/fs/bpf/redirect_map eth2 eth3
```

4. Verify the program is loaded:
```bash
ip link show eth1
# Should show [xdp] in the output
```

5. Monitor the load balancer activity:
```bash
sudo cat /sys/kernel/debug/tracing/trace_pipe
```

## Monitoring and Debugging

- View program logs:
```bash
sudo cat /sys/kernel/debug/tracing/trace_pipe
```

- Check map contents:
```bash
sudo bpftool map dump pinned /sys/fs/bpf/redirect_map
```

- Remove the XDP program:
```bash
sudo ip link set dev eth1 xdp off
```

## Important Notes

1. Driver Support:
    - Not all network drivers support XDP redirect
    - The hv_netvsc driver (Hyper-V) supports basic XDP but not redirect operations
    - Check your driver capabilities with `ethtool -i <interface>`

2. Performance Considerations:
    - This is a basic round-robin implementation
    - Packets from the same connection might go to different interfaces
    - No connection tracking or state management

3. Debug Output:
    - The program logs redirect operations and errors to trace_pipe
    - Monitor trace_pipe to verify operation and troubleshoot issues

## Files Description

- `xdp_loadbalancer.c`: The main XDP program that processes and redirects packets
- `xdp_config.c`: Utility to configure the redirect map with interface indices
- `Makefile`: Build configuration for both programs

## Cleaning Up

To remove compiled files:
```bash
make clean
```

To remove the loaded XDP program:
```bash
sudo ip link set dev eth1 xdp off
```

## Limitations

1. IPv4 only - non-IPv4 packets are passed through
2. No connection tracking - packets from the same connection might go to different interfaces
3. Driver support required for XDP redirect operations
4. Basic round-robin distribution without considering packet size or interface load

## Troubleshooting

1. If `bpftool map list` shows no maps:
    - Ensure bpf filesystem is mounted
    - Verify XDP program is loaded correctly

2. If no packets are being redirected:
    - Check driver support for XDP redirect
    - Verify interface indices in the redirect map
    - Monitor trace_pipe for error messages

3. If compilation fails:
    - Verify all dependencies are installed
    - Check kernel headers match running kernel