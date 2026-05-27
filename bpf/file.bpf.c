#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>

#define COMM_LEN 16
#define MAX_PATH_LEN 256

struct file_event {
  __u64 timestamp;
  __u64 cgroup_id;
  __u32 pid;
  __u32 ppid;
  __u32 uid;
  __u32 gid;
  __s32 dfd;
  __u32 flags;
  char comm[COMM_LEN];
  char filename[MAX_PATH_LEN];
};

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 1 << 24);
} file_events SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_openat")
int handle_openat(struct trace_event_raw_sys_enter *ctx) {
  struct file_event *event;
  struct task_struct *task;
  const char *filename;
  __u64 pid_tgid;
  __u64 uid_gid;

  event = bpf_ringbuf_reserve(&file_events, sizeof(*event), 0);
  if (!event)
    return 0;

  pid_tgid = bpf_get_current_pid_tgid();
  uid_gid = bpf_get_current_uid_gid();

  event->timestamp = bpf_ktime_get_ns();
  event->cgroup_id = bpf_get_current_cgroup_id();
  event->pid = pid_tgid >> 32;
  event->uid = uid_gid;
  event->gid = uid_gid >> 32;
  event->dfd = (__s32)ctx->args[0];
  event->flags = (__u32)ctx->args[2];

  task = (struct task_struct *)bpf_get_current_task();
  event->ppid = BPF_CORE_READ(task, real_parent, tgid);

  bpf_get_current_comm(&event->comm, sizeof(event->comm));

  filename = (const char *)ctx->args[1];
  bpf_probe_read_user_str(event->filename, sizeof(event->filename), filename);

  bpf_ringbuf_submit(event, 0);
  return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
