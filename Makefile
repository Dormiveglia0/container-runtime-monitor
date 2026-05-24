.PHONY: generate build run clean

VMLINUX := bpf/vmlinux.h

$(VMLINUX):
	mkdir -p bpf
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $(VMLINUX)

generate: $(VMLINUX)
	go generate ./internal/collector

build: generate
	mkdir -p bin
	go build -o bin/agent ./cmd/agent

run: build
	./bin/agent

clean:
	rm -rf bin
	rm -f internal/collector/execve_bpfel.go
	rm -f internal/collector/execve_bpfel.o
