#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>

#define COMM_LEN 16
#define MAX_FILENAME_LEN 256
#define MAX_ARGS 6
#define MAX_ARG_LEN 64

struct exec_event {
  __u64 timestamp;
  __u64 cgroup_id;
  __u32 pid;
  __u32 ppid;
  __u32 uid;
  __u32 gid;
  char comm[COMM_LEN];
  char filename[MAX_FILENAME_LEN];
  char argv[MAX_ARGS][MAX_ARG_LEN];
  __u32 argc;
};

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 1 << 24);
} events SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_execve")
int handle_execve(struct trace_event_raw_sys_enter *ctx) {
  struct exec_event *event;
  __u64 pid_tgid;
  __u64 uid_gid;
  struct task_struct *task;
  const char *filename;
  const char *const *argv;

  event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
  if (!event)
    return 0;

  pid_tgid = bpf_get_current_pid_tgid();
  uid_gid = bpf_get_current_uid_gid();

  event->timestamp = bpf_ktime_get_ns();
  event->cgroup_id = bpf_get_current_cgroup_id();
  event->pid = pid_tgid >> 32;
  event->uid = uid_gid;
  event->gid = uid_gid >> 32;
  event->argc = 0;

  task = (struct task_struct *)bpf_get_current_task();
  event->ppid = BPF_CORE_READ(task, real_parent, tgid);

  bpf_get_current_comm(&event->comm, sizeof(event->comm));

  filename = (const char *)ctx->args[0];
  argv = (const char *const *)ctx->args[1];

  bpf_probe_read_user_str(event->filename, sizeof(event->filename), filename);

  for (int i = 0; i < MAX_ARGS; i++) {
    const char *argp = 0;

    if (bpf_probe_read_user(&argp, sizeof(argp), &argv[i]) < 0)
      break;

    if (!argp)
      break;

    if (bpf_probe_read_user_str(event->argv[i], MAX_ARG_LEN, argp) > 0)
      event->argc++;
  }

  bpf_ringbuf_submit(event, 0);
  return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
