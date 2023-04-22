#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct event_t {
  char path[50];
  char name[50];
  char value[50];
};

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 4096);
  __type(key, u64);
  __type(value, struct event_t);
} storage SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
  __uint(max_entries, 4096);
  __type(key, u32);
  __type(value, u32);
} events SEC(".maps");

// Try to extract PWD or the dentry
int set_attr_enter(struct trace_event_raw_sys_enter *ctx) {
  struct event_t event = {0};

  // We could validate them here for speed
  bpf_probe_read_user_str(event.path, sizeof(event.path), (void *)ctx->args[0]);
  bpf_probe_read_user_str(event.name, sizeof(event.name), (void *)ctx->args[1]);
  bpf_probe_read_user_str(event.value, sizeof(event.value),
                          (void *)ctx->args[2]);

  // bpf_printk("=path: %s", event.path);
  // bpf_printk("=name: %s", event.name);
  // bpf_printk("=value: %s", event.value);

  u64 key = bpf_get_current_pid_tgid();
  bpf_map_update_elem(&storage, &key, &event, BPF_ANY);

  return 0;
}

int set_attr_exit(struct trace_event_raw_sys_exit *ctx) {
  if (ctx->ret != 0) {
    return 1;
  }

  u64 key = bpf_get_current_pid_tgid();
  struct event_t *event = bpf_map_lookup_elem(&storage, &key);
  if (event == NULL) {
    return 1;
  }

  bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event,
                        sizeof(struct event_t));

  bpf_map_delete_elem(&storage, &key);
  return 0;
}

// setxattr
SEC("tracepoint/syscalls/sys_enter_setxattr")
int sys_enter_setxattr(struct trace_event_raw_sys_enter *ctx) {
  return set_attr_enter(ctx);
}

SEC("tracepoint/syscalls/sys_exit_setxattr")
int sys_exit_setxattr(struct trace_event_raw_sys_exit *ctx) {
  return set_attr_exit(ctx);
}

// lsetxattr
SEC("tracepoint/syscalls/sys_enter_lsetxattr")
int sys_enter_lsetxattr(struct trace_event_raw_sys_enter *ctx) {
  return set_attr_enter(ctx);
}

SEC("tracepoint/syscalls/sys_exit_lsetxattr")
int sys_exit_lsetxattr(struct trace_event_raw_sys_exit *ctx) {
  return set_attr_exit(ctx);
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";