package collector

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -go-package collector -output-dir . Execve ../../bpf/execve.bpf.c -- -I../../bpf -O2 -g
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -go-package collector -output-dir . File ../../bpf/file.bpf.c -- -I../../bpf -O2 -g
