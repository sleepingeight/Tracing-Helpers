#include <stdio.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/types.h>
#include "trace_helpers.h"

void read_trace_pipe(void)
{
  int trace_fd;

  trace_fd = open("/sys/kernel/debug/tracing/trace_pipe", O_RDONLY, 0);
  if(trace_fd < 0){
    printf("Blocked mp\n");
    return;
  }
    
  
  while(1){
    static char buf[4096];
    ssize_t sz;

    sz = read(trace_fd, buf, sizeof(buf)-1);
    if(sz > 0){
      buf[sz] = 0;
      puts(buf);
    }
  }

}


int main(int agrc, char **argv)
{
  struct bpf_link *link = NULL;
  struct bpf_program *prog;
  struct bpf_object *obj;
  char filename[256];
  FILE *f;
  
  snprintf(filename, sizeof(filename), "%s.bpf.o", argv[0]);
  obj = bpf_object__open_file(filename, NULL);
  if(libbpf_get_error(obj)){
    fprintf(stderr, "ERROR: opening BPF object file failed\n");
    return 0;
  }
  
  prog = bpf_object__find_program_by_name(obj, "bpf_prog1");
  if(!prog){
    fprintf(stderr, "ERROR: finding prog in obj file failed\n");
  }
  
  /* loading BPF program */
  if(bpf_object__load(obj)){
    fprintf(stderr, "ERROR: loading BPF object file failed\n");
    goto cleanup;
  }
  
  link = bpf_program__attach(prog);
  if(libbpf_get_error(link)){
    fprintf(stderr, "ERROR: bpf_program__attach failed\n");
    link  = NULL;
    goto cleanup;
  }
  
  read_trace_pipe();
  
  


cleanup:
  bpf_link__destroy(link);
  bpf_object__close(obj);
  return 0;
  
}


// sudo cat /sys/kernel/debug/kprobes/list
// sudo cat /proc/kallsyms | grep bpf_ktime_get_ns