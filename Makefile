.PHONY: generate build build-web web run clean

VMLINUX := bpf/vmlinux.h

$(VMLINUX):
	mkdir -p bpf
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $(VMLINUX)

generate: $(VMLINUX)
	go generate ./internal/collector

build: generate
	mkdir -p bin
	go build -buildvcs=false -o bin/agent ./cmd/agent

build-web:
	mkdir -p bin
	go build -buildvcs=false -o bin/web ./cmd/web

web: build-web
	./bin/web -db data/monitor.db -addr :8080

run: build
	./bin/agent

clean:
	rm -rf bin
	rm -f internal/collector/execve_bpfel.go
	rm -f internal/collector/execve_bpfel.o
	rm -f internal/collector/file_bpfel.go
	rm -f internal/collector/file_bpfel.o
