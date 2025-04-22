 // exec_event 구조체가 선언된 헤더 포함  

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "common.h"

static volatile sig_atomic_t exiting = 0;

void handle_event(void *ctx, int cpu, void *data, __u32 data_sz) {
    struct exec_event *e = data;
    printf("[execve] pid=%d uid=%d comm=%s\n", e->pid, e->uid, e->comm);
}

void handle_lost(void *ctx, int cpu, __u64 lost_cnt) {
    fprintf(stderr, "Lost %llu events on CPU %d\n", lost_cnt, cpu);
}

void sig_handler(int signo) {
    exiting = 1;
}

int main() {
    struct bpf_object *obj;
    int map_fd;
    struct perf_buffer *pb;

    signal(SIGINT, sig_handler);

    obj = bpf_object__open_file("exec_monitor.bpf.o", NULL);
    if (!obj) {
        fprintf(stderr, "Failed to open BPF object file\n");
        return 1;
    }

    if (bpf_object__load(obj)) {
        fprintf(stderr, "Failed to load BPF object\n");
        return 1;
    }

    map_fd = bpf_object__find_map_fd_by_name(obj, "exec_events");
    if (map_fd < 0) {
        fprintf(stderr, "Failed to find map\n");
        return 1;
    }

    pb = perf_buffer__new(map_fd, 8, handle_event, handle_lost, NULL, NULL);
    if (!pb) {
        fprintf(stderr, "Failed to create perf buffer\n");
        return 1;
    }

    while (!exiting) {
        perf_buffer__poll(pb, 100);
    }

    perf_buffer__free(pb);
    bpf_object__close(obj);
    return 0;
}