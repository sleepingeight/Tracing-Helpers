#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <linux/version.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>




SEC("kprobe/bpf_ktime_get_ns")
int bpf_prog1(struct pt_regs *ctx)
{
  static const char s[] = "Traced\n";
  bpf_trace_printk(s, sizeof(s));
  return 0;
}

char _license[] SEC("license") = "GPL";
u32 _version SEC("version") = LINUX_VERSION_CODE;
