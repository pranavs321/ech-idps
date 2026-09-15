# Build the XDP object file. Requires clang + libbpf headers.
#   sudo apt install clang llvm libbpf-dev linux-tools-$(uname -r)

ARCH := $(shell uname -m | sed 's/x86_64/__x86_64__/;s/aarch64/__aarch64__/')
CLANG ?= clang
CFLAGS := -O2 -g -Wall -target bpf -D$(ARCH) -I/usr/include

xdp_filter.o: xdp_filter.c
	$(CLANG) $(CFLAGS) -c $< -o $@
	@echo "built $@  --  load with: sudo python3 -m idps.module1_dataplane.loader --iface <IFACE>"

clean:
	rm -f xdp_filter.o

.PHONY: clean
