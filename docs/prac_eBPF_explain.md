> 간단하게 프로세스 시작 되었을 때를 기준으로 연습을 해보자
> 

### common.h

> **역할:**
eBPF 프로그램과 사용자 영역에서 공유하는 exec_event 구조체 정의
→ 커널 ↔ 사용자 간 통신을 위한 **데이터 포맷 통일 목적**
> 

```c
// 얘는 왜 시스템 파일이야
#include <vmlinux.h>
// 만약에 COMMON 헤더 파일이 정의가 안되었다면 정의할게요
#ifndef __COMMON_H
#define __COMMON_H

struct exec_event {

    u32 pid;
    u32 uid;
    // 프로세스 이름 ( 최대 15자 +\0 = 16바이트)
    // ps 명령에서 나오는 "COMMAND" 컬럼이랑 비슷한 역할
    char comm[16];
};

#endif
```

### exec_monitor.bpf.c

> 역할:
execve() 시스템 콜이 발생했을 때, 프로세스 정보를 캡처하여
perf buffer를 통해 사용자 영역에 전달
> 

```c
// 커널 구조체 참조용으로 BTF에서 추출한 것
#include "vmlinux.h"

// 시스템 경로로 bpf/헤더 넣은 건 직접 설치한 libbpf-dev를 통해
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

// 사용자 정의 구조체를 커널과 유저 영역 모두 공유하기 위해 사용
#include "common.h"

// BPF 프로그램이 커널에 attach 되기 위한 라이선스 정보
// 커널은 GPL로 동작중
// GPL 전용 헬퍼를 사용하기 위해 명시해야함
// 안넣으면 verifier 로딩 자체를 거부
char LICENSE[] SEC("license") = "GPL";

// map 정의 부분
// BPF_MAP_TYPE_PERF_EVENT_ARRAY는 perf buffer 기반의 이벤트 전송 구조
// 이 map은 커널->사용자 영역으로 데이터를 푸시하기 위한 링버퍼 역할을 함
// map 자체는 커널 안에 있으나, SEC(".maps")로 BPF ELF 바이너리에서 map으로 인식
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} exec_events SEC(".maps");

// 정적 tracepoint에 attach
SEC("tracepoint/syscalls/sys_enter_execve")

// ctx = 현재 시스템 콜 진입 당시의 상태 정보를 담은 구조체 포인터
// 정적 tracepoint랑 동적 tracepoint랑 ctx 구조가 다름
int handle_execve(struct trace_event_raw_sys_enter *ctx)
{
    struct exec_event evt ={};
    evt.pid = bpf_get_current_pid_tgid() >> 32;
    evt.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    bpf_get_current_comm(&evt.comm, sizeof(evt.comm));

    bpf_perf_event_output(ctx, &exec_events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));
    return 0;
}
```

### exec_loader.c

> 역할:eBPF 바이트코드(.bpf.o)를
**커널에 로드하고**
perf buffer를 통해 전달된 이벤트를 **유저 영역에서 출력하는 로더 프로그램**
> 

```c
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
```