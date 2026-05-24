package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"container-runtime-monitor/internal/collector"
	containerctx "container-runtime-monitor/internal/container"
	"container-runtime-monitor/internal/rule"
	"container-runtime-monitor/internal/storage"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

const (
	commLen        = 16
	maxFilenameLen = 256
	maxArgs        = 6
	maxArgLen      = 64
)

type execEvent struct {
	Timestamp uint64
	CgroupID  uint64
	PID       uint32
	PPID      uint32
	UID       uint32
	GID       uint32
	Comm      [commLen]byte
	Filename  [maxFilenameLen]byte
	Argv      [maxArgs][maxArgLen]byte
	Argc      uint32
}

func main() {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("remove memlock limit: %v", err)
	}

	var objs collector.ExecveObjects
	if err := collector.LoadExecveObjects(&objs, nil); err != nil {
		log.Fatalf("load eBPF objects: %v", err)
	}
	defer objs.Close()

	tp, err := link.Tracepoint("syscalls", "sys_enter_execve", objs.HandleExecve, nil)
	if err != nil {
		log.Fatalf("attach tracepoint: %v", err)
	}
	defer tp.Close()

	store, err := storage.Open("data/monitor.db")
	if err != nil {
		log.Fatalf("open sqlite database: %v", err)
	}
	defer store.Close()

	reader, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Fatalf("open ring buffer: %v", err)
	}
	defer reader.Close()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-stop
		reader.Close()
	}()

	fmt.Println("container runtime monitor started")
	fmt.Println("listening for execve events from Docker containers...")

	for {
		record, err := reader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			log.Printf("read ring buffer: %v", err)
			continue
		}

		var event execEvent
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &event); err != nil {
			log.Printf("decode event: %v", err)
			continue
		}

		containerID := containerctx.ResolveDockerContainerID(event.PID)
		if !containerctx.IsContainerProcess(containerID) {
			continue
		}

		filename := cString(event.Filename[:])
		comm := cString(event.Comm[:])
		args := argvToStrings(event.Argv, event.Argc)

		fmt.Printf(
			"[EXEC] container=%s pid=%d ppid=%d uid=%d comm=%s file=%s args=%s\n",
			containerctx.ShortID(containerID),
			event.PID,
			event.PPID,
			event.UID,
			comm,
			filename,
			formatArgs(args),
		)

		eventID, err := store.InsertExecEvent(storage.ExecEvent{
			Timestamp:   event.Timestamp,
			PID:         event.PID,
			PPID:        event.PPID,
			UID:         event.UID,
			GID:         event.GID,
			Comm:        comm,
			Filename:    filename,
			Args:        args,
			CgroupID:    event.CgroupID,
			ContainerID: containerID,
		})
		if err != nil {
			log.Printf("insert exec event: %v", err)
		}

		if alert := rule.MatchExec(filename, args, containerID); alert != nil {
			fmt.Printf(
				"[ALERT] severity=%s rule=%s container=%s pid=%d message=%s\n",
				alert.Severity,
				alert.RuleID,
				containerctx.ShortID(containerID),
				event.PID,
				alert.Message,
			)

			if err := store.InsertAlert(storage.AlertEvent{
				Timestamp:   event.Timestamp,
				RuleID:      alert.RuleID,
				Severity:    alert.Severity,
				Message:     alert.Message,
				ContainerID: containerID,
				PID:         event.PID,
				EventID:     eventID,
			}); err != nil {
				log.Printf("insert alert: %v", err)
			}
		}
		// if alert := rule.MatchExec(filename, args, containerID); alert != nil {
		// 	fmt.Printf(
		// 		"[ALERT] severity=%s rule=%s container=%s pid=%d message=%s\n",
		// 		alert.Severity,
		// 		alert.RuleID,
		// 		containerctx.ShortID(containerID),
		// 		event.PID,
		// 		alert.Message,
		// 	)
		// }
	}
}

func cString(raw []byte) string {
	idx := bytes.IndexByte(raw, 0)
	if idx == -1 {
		idx = len(raw)
	}
	return string(raw[:idx])
}

func argvToStrings(raw [maxArgs][maxArgLen]byte, argc uint32) []string {
	args := make([]string, 0, maxArgs)

	limit := int(argc)
	if limit > maxArgs {
		limit = maxArgs
	}

	for i := 0; i < limit; i++ {
		arg := cString(raw[i][:])
		if arg != "" {
			args = append(args, arg)
		}
	}

	return args
}

func formatArgs(args []string) string {
	if len(args) == 0 {
		return "[]"
	}

	quoted := make([]string, 0, len(args))
	for _, arg := range args {
		quoted = append(quoted, fmt.Sprintf("%q", arg))
	}

	return "[" + strings.Join(quoted, ", ") + "]"
}
