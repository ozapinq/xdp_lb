# Compiler and flags
CLANG ?= clang
LLC ?= llc
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

BPF_CFLAGS ?= -I/usr/include/bpf \
              -I/usr/include/linux

# Output binary name
BIN := xdp_loadbalancer

# Source files
SRC := xdp_loadbalancer.c
CONFIG_SRC := xdp_config.c
BPF_OBJ := ${BIN}.o
CONFIG_BIN := xdp_config

# Linker flags for config tool
LDFLAGS := -lbpf

# Default target
all: $(BPF_OBJ) $(CONFIG_BIN)

$(CONFIG_BIN): $(CONFIG_SRC)
	$(CC) $(CFLAGS) $< $(LDFLAGS) -o $@


# Compile BPF program
$(BPF_OBJ): $(SRC)
	$(CLANG) -S \
		-target bpf \
		-D __BPF_TRACING__ \
		$(BPF_CFLAGS) \
		-Wall \
		-Wno-unused-value \
		-Wno-pointer-sign \
		-Wno-compare-distinct-pointer-types \
		-O2 -emit-llvm -c -g -o ${BIN}.ll $<
	$(LLC) -march=bpf -filetype=obj -o $@ ${BIN}.ll

# Clean built files
clean:
	rm -f $(BPF_OBJ) ${BIN}.ll

.PHONY: all clean
