package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

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
	maxPathLen     = 256
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

type fileEvent struct {
	Timestamp uint64
	CgroupID  uint64
	PID       uint32
	PPID      uint32
	UID       uint32
	GID       uint32
	Dfd       int32
	Flags     uint32
	Comm      [commLen]byte
	Filename  [maxPathLen]byte
}

type eventEnvelope struct {
	kind string
	exec execEvent
	file fileEvent
}

func main() {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("remove memlock limit: %v", err)
	}

	var execObjs collector.ExecveObjects
	if err := collector.LoadExecveObjects(&execObjs, nil); err != nil {
		log.Fatalf("load execve eBPF objects: %v", err)
	}
	defer execObjs.Close()

	var fileObjs collector.FileObjects
	if err := collector.LoadFileObjects(&fileObjs, nil); err != nil {
		log.Fatalf("load file eBPF objects: %v", err)
	}
	defer fileObjs.Close()

	execTp, err := link.Tracepoint("syscalls", "sys_enter_execve", execObjs.HandleExecve, nil)
	if err != nil {
		log.Fatalf("attach execve tracepoint: %v", err)
	}
	defer execTp.Close()

	fileTp, err := link.Tracepoint("syscalls", "sys_enter_openat", fileObjs.HandleOpenat, nil)
	if err != nil {
		log.Fatalf("attach openat tracepoint: %v", err)
	}
	defer fileTp.Close()

	store, err := storage.Open("data/monitor.db")
	if err != nil {
		log.Fatalf("open sqlite database: %v", err)
	}
	defer store.Close()

	dockerClient := containerctx.NewDockerClient("/var/run/docker.sock")
	containerResolver := newContainerResolver(dockerClient)

	ruleEngine, err := rule.Load("configs/rules.yaml")
	if err != nil {
		log.Fatalf("load rules: %v", err)
	}

	execReader, err := ringbuf.NewReader(execObjs.Events)
	if err != nil {
		log.Fatalf("open execve ring buffer: %v", err)
	}
	defer execReader.Close()

	fileReader, err := ringbuf.NewReader(fileObjs.FileEvents)
	if err != nil {
		log.Fatalf("open file ring buffer: %v", err)
	}
	defer fileReader.Close()

	events := make(chan eventEnvelope, 1024)
	errs := make(chan error, 2)

	go readExecEvents(execReader, events, errs)
	go readFileEvents(fileReader, events, errs)

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	fmt.Println("container runtime monitor started")
	fmt.Println("listening for execve and sensitive file open events from Docker containers...")

	for {
		select {
		case <-stop:
			return

		case err := <-errs:
			if err != nil && !errors.Is(err, ringbuf.ErrClosed) {
				log.Printf("read event: %v", err)
			}

		case envelope := <-events:
			switch envelope.kind {
			case "execve":
				handleExecEvent(store, containerResolver, ruleEngine, envelope.exec)
			case "file_open":
				handleFileEvent(store, containerResolver, ruleEngine, envelope.file)
			}
		}
	}
}

func readExecEvents(reader *ringbuf.Reader, out chan<- eventEnvelope, errs chan<- error) {
	for {
		record, err := reader.Read()
		if err != nil {
			errs <- err
			return
		}

		var event execEvent
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &event); err != nil {
			errs <- err
			continue
		}

		out <- eventEnvelope{kind: "execve", exec: event}
	}
}

func readFileEvents(reader *ringbuf.Reader, out chan<- eventEnvelope, errs chan<- error) {
	for {
		record, err := reader.Read()
		if err != nil {
			errs <- err
			return
		}

		var event fileEvent
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &event); err != nil {
			errs <- err
			continue
		}

		out <- eventEnvelope{kind: "file_open", file: event}
	}
}

func handleExecEvent(store *storage.Store, resolver *containerResolver, rules *rule.Engine, event execEvent) {
	containerID, metadata, ok := resolver.Resolve(event.PID, event.CgroupID)
	if !ok {
		return
	}

	filename := cString(event.Filename[:])
	comm := cString(event.Comm[:])
	args := argvToStrings(event.Argv, event.Argc)

	fmt.Printf(
		"[EXEC] container=%s name=%s image=%s state=%s pid=%d ppid=%d uid=%d comm=%s file=%s args=%s\n",
		metadata.ShortID,
		metadata.Name,
		metadata.Image,
		metadata.State,
		event.PID,
		event.PPID,
		event.UID,
		comm,
		filename,
		formatArgs(args),
	)

	eventID, err := store.InsertExecEvent(storage.ExecEvent{
		Timestamp:      event.Timestamp,
		PID:            event.PID,
		PPID:           event.PPID,
		UID:            event.UID,
		GID:            event.GID,
		Comm:           comm,
		Filename:       filename,
		Args:           args,
		CgroupID:       event.CgroupID,
		ContainerID:    containerID,
		ContainerName:  metadata.Name,
		ImageName:      metadata.Image,
		ContainerState: metadata.State,
	})
	if err != nil {
		log.Printf("insert exec event: %v", err)
	}

	if alert := rules.MatchExec(filename, args, containerID); alert != nil {
		printAlert(alert, metadata.ShortID, event.PID)

		if err := store.InsertAlert(storage.AlertEvent{
			Timestamp:      event.Timestamp,
			RuleID:         alert.RuleID,
			Severity:       alert.Severity,
			Message:        alert.Message,
			ContainerID:    containerID,
			ContainerName:  metadata.Name,
			ImageName:      metadata.Image,
			ContainerState: metadata.State,
			PID:            event.PID,
			EventID:        eventID,
		}); err != nil {
			log.Printf("insert alert: %v", err)
		}
	}
}

func handleFileEvent(store *storage.Store, resolver *containerResolver, rules *rule.Engine, event fileEvent) {
	path := cString(event.Filename[:])
	if path == "" {
		return
	}

	containerID, metadata, ok := resolver.Resolve(event.PID, event.CgroupID)
	if !ok {
		return
	}

	comm := cString(event.Comm[:])
	if rules.IgnoreFile(comm, path) {
		return
	}

	alert := rules.MatchFile(path, event.Flags, containerID)
	if alert == nil {
		return
	}

	fmt.Printf(
		"[FILE] container=%s name=%s image=%s state=%s pid=%d ppid=%d uid=%d comm=%s path=%s flags=0x%x\n",
		metadata.ShortID,
		metadata.Name,
		metadata.Image,
		metadata.State,
		event.PID,
		event.PPID,
		event.UID,
		comm,
		path,
		event.Flags,
	)

	eventID, err := store.InsertFileEvent(storage.FileEvent{
		Timestamp:      event.Timestamp,
		PID:            event.PID,
		PPID:           event.PPID,
		UID:            event.UID,
		GID:            event.GID,
		Comm:           comm,
		Path:           path,
		Flags:          event.Flags,
		CgroupID:       event.CgroupID,
		ContainerID:    containerID,
		ContainerName:  metadata.Name,
		ImageName:      metadata.Image,
		ContainerState: metadata.State,
	})
	if err != nil {
		log.Printf("insert file event: %v", err)
	}

	printAlert(alert, metadata.ShortID, event.PID)

	if err := store.InsertAlert(storage.AlertEvent{
		Timestamp:      event.Timestamp,
		RuleID:         alert.RuleID,
		Severity:       alert.Severity,
		Message:        alert.Message,
		ContainerID:    containerID,
		ContainerName:  metadata.Name,
		ImageName:      metadata.Image,
		ContainerState: metadata.State,
		PID:            event.PID,
		EventID:        eventID,
	}); err != nil {
		log.Printf("insert alert: %v", err)
	}
}

type resolvedContainer struct {
	id       string
	metadata containerctx.Metadata
}

type containerResolver struct {
	dockerClient *containerctx.DockerClient
	byCgroupID   map[uint64]resolvedContainer
	mu           sync.RWMutex
}

func newContainerResolver(dockerClient *containerctx.DockerClient) *containerResolver {
	return &containerResolver{
		dockerClient: dockerClient,
		byCgroupID:   make(map[uint64]resolvedContainer),
	}
}

func (r *containerResolver) Resolve(pid uint32, cgroupID uint64) (string, containerctx.Metadata, bool) {
	containerID := containerctx.ResolveDockerContainerID(pid)
	if containerctx.IsContainerProcess(containerID) {
		metadata := r.inspect(containerID)

		if cgroupID != 0 {
			r.mu.Lock()
			r.byCgroupID[cgroupID] = resolvedContainer{
				id:       containerID,
				metadata: metadata,
			}
			r.mu.Unlock()
		}

		return containerID, metadata, true
	}

	if cgroupID != 0 {
		r.mu.RLock()
		cached, ok := r.byCgroupID[cgroupID]
		r.mu.RUnlock()

		if ok {
			return cached.id, cached.metadata, true
		}
	}

	return "", containerctx.Metadata{}, false
}

func (r *containerResolver) inspect(containerID string) containerctx.Metadata {
	inspectCtx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	metadata, err := r.dockerClient.Inspect(inspectCtx, containerID)
	cancel()

	if err != nil {
		log.Printf("inspect container %s: %v", containerctx.ShortID(containerID), err)
		return containerctx.Metadata{
			ID:      containerID,
			ShortID: containerctx.ShortID(containerID),
		}
	}

	return metadata
}

func isRuntimeFileNoise(comm string, path string) bool {
	if strings.HasPrefix(path, "/var/lib/docker/") {
		return true
	}

	if strings.HasPrefix(comm, "runc") {
		switch {
		case path == "/proc/kcore":
			return true
		case path == "/etc/passwd":
			return true
		case strings.HasPrefix(path, "/var/lib/docker/"):
			return true
		}
	}

	return false
}

func printAlert(alert *rule.Alert, containerID string, pid uint32) {
	fmt.Printf(
		"[ALERT] severity=%s rule=%s container=%s pid=%d message=%s\n",
		alert.Severity,
		alert.RuleID,
		containerID,
		pid,
		alert.Message,
	)
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
