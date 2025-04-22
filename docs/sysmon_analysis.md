### Sysmon은 과제를 어떻게 풀고 있나

### Sysmon - ProcessCreate

sysmon은 프로세스가 생성될 때

sysmon이 감지하고 생성한 로그에 아래와 같은 메타데이터 필드가 포함됨

→ execve() 시스템 콜을 후킹하거나 tracepoint로 감지했을 때

→ 해당 프로세스에 대한 정보가 아래와 같은 필드들로 구성된 이벤트 구조체로 정리

| **필드명** | **설명** |
| --- | --- |
| UtcTime | 이벤트 발생 시간 (UTC 기준) |
| ProcessGuid | 고유한 GUID (글로벌 식별자) — 프로세스 추적용 |
| ProcessId | 생성된 프로세스의 PID |
| ParentProcessId | 부모 프로세스의 PID |
| CommandLine | 실행된 커맨드 전체 |
| Image | 실행된 바이너리 경로 (예: /usr/bin/bash) |
| User | 프로세스를 실행한 사용자 |
| CurrentDirectory | 해당 명령이 실행된 디렉토리 |
| LogonId | 로그인 세션 식별자 |
| IntegrityLevel | 권한 수준 (예: root, 일반 사용자) |
| Hashes | 실행 파일의 해시값 (보안 목적) |
| ParentCommandLine | 부모 프로세스의 실행 커맨드 |

```c
#include "sysmonEBPF_common.h"
#include <sysinternalsEBPF_helpers.c>
#include "sysmonHelpers.c"
#include "sysmonProcCreate.c"

// sys_exit에 attach (system call 종료 시점)
SEC("raw_tracepoint/sys_exit")
__attribute__((flatten))
// 시스템 콜 종료 시 커널이 전달하는 레지스터 상태 포인터 배열
int ProcCreateRawExit(struct bpf_our_raw_tracepoint_args *ctx)
{
		// 상위 32비트 pid(process id) + 하위 32비트 tid(thread id) = 64 비트 가져오기
		// 이 값이 map의 키로 많이 쓰임
    uint64_t pidTid = bpf_get_current_pid_tgid();
    
    // 현재 이 BPF 함수가 실행 중인 CPU 번호
    // eBPF의 per-CPU map에 접근할 때 인덱스로 사용
    uint32_t cpuId = bpf_get_smp_processor_id();
    
    // 이벤트의 시작 부분을 의미하는 구조체 (아직 map에서 안 꺼내서 NULL)
    PSYSMON_EVENT_HEADER eventHdr = NULL;
    
    // syscall 인자 구조체 포인터 선언 (아직 map에서 안 꺼내서 NULL)
    argsStruct *eventArgs = NULL;
    
    // process trace_registers (커널에서 시스템 콜, 인터럽트, 트랩 처리시 CPU의 레지스터 상태)
    // 시스템 콜 호출 당시의 레지스터 값을 담은 스냅샷 구조체
    // ctx->args[0] => syscall 종료 시 전달된 첫 번째 인자 (레지스터 상태 주소)
    // 그걸 pt_regs* 타입으로 캐스팅해서 저장 (단순 숫자형 주소이기에 형변환 필요)
    // regs 변수에는 레지스터 정보가 담긴 구조체의 주소
    const struct pt_regs *regs = (const struct pt_regs *)ctx->args[0];
    
    const ebpfConfig *config;
    
    // ptr은 구조체에서 어떤 데이터를 추가해나갈 때 위치 추적용 포인터로 사용
    char *ptr = NULL;
    
    // config 변수의 메모리 주소, eventArgs 변수의 메모리 주소
    if (!setUpEvent(&config, &eventArgs)) {
        return 0;
    }

    // only handle process creation events
    // eventArgs 자체는 구조체의 주소를 담는 변수이지만 -> 연산으로 인해 syscallId 호출 가능
    if (eventArgs->syscallId != __NR_execve &&
        eventArgs->syscallId != __NR_execveat) {
        return 0;
    }

    // set the return code
    // 간접적으로 읽을려고 helper 사용
    // 시스템 콜 리턴값이 들어 있는 메모리를 읽기 위한 eBPF 표준 방식
    // 
    if (bpf_probe_read(
			     &eventArgs->returnCode,
			     sizeof(int64_t), 
					 (void *)&SYSCALL_PT_REGS_RC(regs)) != 0){
        BPF_PRINTK("ERROR, failed to get return code\n");
    }

    if (!getEventHdr(&eventHdr, cpuId)) {
        return 0;
    }

    ptr = set_ProcCreate_info(eventHdr, config, pidTid, cpuId, eventArgs);
    if (ptr != NULL && ptr > eventHdr) {
        eventHdr->m_EventSize = (uint32_t)((void *)ptr - (void *)eventHdr);
        checkAndSendEvent((void *)ctx, eventHdr, config);
    }

    // Cleanup hash as we handled this event
    bpf_map_delete_elem(&argsHash, &pidTid);

    return 0;
}
```

### header 파일부터 뜯어보자

```c
//====================================================================
//
// sysmonEBPF_common.h
//
// Includes and maps used by all eBPF programs.
//
//====================================================================

// Header Guard
// 여러 .c 파일에서 중복 include 되는 걸 막기 위한 전통적인 C 관례
// 처음 include되면 SYSMON_EBPF_COMMON_H 정의되고, 두번째부터는 무시 됨
#ifndef SYSMON_EBPF_COMMON_H
#define SYSMON_EBPF_COMMON_H

// eBPF용 컴파일 설정 조건
#define SYSMON_EBPF

// ifdef -> 커널의 빌드 환경이 어떤지에 따라, 포함할 헤더파일이나 사용하는 방식이 달라짐
// 만약 EBPF_CO_RE 매크로가 이미 정의되어 있다면 두개의 헤더파일만 아니면 그 밑에
// 시스템 헤더 파일을 포함시키기
#ifdef EBPF_CO_RE
#include "vmlinux.h"
#include "vmlinux_kern_diffs.h"
#else
#include <linux/version.h>
#include <linux/bpf.h>
#include <linux/socket.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/fcntl.h>
#include <sys/socket.h>
#include <linux/string.h>
#include <asm/ptrace.h>
#endif

#include <sysinternalsEBPF_common.h>
#include <stdint.h>
#include <bpf_helpers.h>
#include <bpf_core_read.h>
#include <asm/unistd_64.h>
#include <sysinternalsEBPFshared.h>
#include "sysmon_defs.h"

#define LINUX_MAX_EVENT_SIZE (65536 - 24)

// defining file mode locally to remove requirement for heavy includes.
// note that these *could* change, *but really aren't likely to*!
#define S_IFMT      00170000
#define S_IFREG      0100000
#define S_IFBLK      0060000
#define S_IFSOCK     0140000

// create a map to hold the event as we build it - too big for stack
// one entry per cpu
// 커널에서 이벤트를 만들고 저장할 map 정의 (stack에 올리기엔 너무 큼)
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);   // map의 타입: 배열
    __uint(key_size, sizeof(uint32_t));   // key의 크기 (int 하나)
    __uint(value_size, LINUX_MAX_EVENT_SIZE);  // value 크기 (이벤트 전체 사이즈)
    __uint(max_entries, MAX_PROC);  // map의 엔트리 수 (예: CPU 수만큼)
} eventStorageMap SEC(".maps");  // ".maps" 섹션으로 컴파일

// create a map to hold the args as we build it - too big for stack
// one entry per cpu
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, uint32_t);
    __type(value, argsStruct);
    __uint(max_entries, MAX_PROC);
} argsStorageMap SEC(".maps");

// create a map to hold the packet as we access it - eBPF doesn't like
// arbitrary access to stack buffers
// one entry per cpu
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(key_size, sizeof(uint32_t));
    __uint(value_size, PACKET_SIZE);
    __uint(max_entries, MAX_PROC);
} packetStorageMap SEC(".maps");

// create a map to hold the UDP recv age information
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, UDP_HASH_SIZE);
    __type(key, uint64_t);
    __type(value, uint64_t);
} UDPrecvAge SEC(".maps");

// create a map to hold the UDP send age information
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, UDP_HASH_SIZE);
    __type(key, uint64_t);
    __type(value, uint64_t);
} UDPsendAge SEC(".maps");

#endif
```

### helper 분리를 왜 했을까

```c
#ifndef SYSMON_HELPERS_C
#define SYSMON_HELPERS_C

// Sysmon-specific inline helper functions

//--------------------------------------------------------------------
//
// getConfig
//
// Obtain the PID/TID and retrieve the config. Check that the PID
// isn't the same as the Sysmon process.
//
//--------------------------------------------------------------------
__attribute__((always_inline))
static inline bool getConfig(const ebpfConfig **config, uint64_t *pidTid)
{
    uint32_t configId = 0;

    *pidTid = bpf_get_current_pid_tgid();

    // retrieve config
    *config = bpf_map_lookup_elem(&configMap, &configId);
    if (*config == NULL) {
        return false;
    }

    // don't report any syscalls for the userland PID
    if (((*pidTid) >> 32) == (*config)->userlandPid) {
        return false;
    }

    return true;
}

//--------------------------------------------------------------------
//
// setUpEvent
//
// Get the config and retrieve the stored syscall arguments.
//
//--------------------------------------------------------------------
__attribute__((always_inline))
static inline bool setUpEvent(const ebpfConfig **config, argsStruct **eventArgs)
{
    uint64_t pidTid = 0;

    if (!getConfig(config, &pidTid)) {
        return false;
    }

    // retrieve map storage for event args
    // this was created on the preceding sys_enter
    // if the pidTid is in our map then we must have stored it
    *eventArgs = bpf_map_lookup_elem(&argsHash, &pidTid);
    if (*eventArgs == NULL) {
        return false;
    }

    return true;
}

//--------------------------------------------------------------------
//
// getEventHdr
//
// Locate the temporary storage for the event as we build it.
//
//--------------------------------------------------------------------
__attribute__((always_inline))
static inline bool getEventHdr(PSYSMON_EVENT_HEADER *eventHdr, uint32_t cpuId)
{
    // retrieve map storage for event
    *eventHdr = bpf_map_lookup_elem(&eventStorageMap, &cpuId);
    if (!*eventHdr) {
        return false;
    }

    return true;
}

//--------------------------------------------------------------------
//
// checkAndSendEvent
//
// Check the size of the event is within limits, then send it.
// Note, eventOutput monitors for perf ring buffer errors and records
// them in the perf error map.
//
//--------------------------------------------------------------------
__attribute__((always_inline))
static inline void checkAndSendEvent(void *ctx, const PSYSMON_EVENT_HEADER eventHdr, const ebpfConfig *config)
{
    size_t size = eventHdr->m_EventSize;
    eventOutput(ctx, &eventMap, BPF_F_CURRENT_CPU, eventHdr, size < LINUX_MAX_EVENT_SIZE ? size : 0);
}

//--------------------------------------------------------------------
//
// checkAndSendEventNoError
//
// Check the size of the event is within limits, then send it directly
// without going through the error handler.
//
//--------------------------------------------------------------------
__attribute__((always_inline))
static inline void checkAndSendEventNoError(void *ctx, const PSYSMON_EVENT_HEADER eventHdr, const ebpfConfig *config)
{
    size_t size = eventHdr->m_EventSize;
    bpf_perf_event_output(ctx, &eventMap, BPF_F_CURRENT_CPU, eventHdr, size < LINUX_MAX_EVENT_SIZE ? size : 0);
}
 
#endif
```

- 일단 기본적으로 eBPF는 커널 단에서 실행이 되는 코드지만 엄연히 커널 안에 샌드박스에서 진행되기에
커널처럼 활동이 되는건 아니다. 제약이 있다. 그 결과가 hw에 직접적인 접근은 안된다.
- 커널 리소스에 직접적인 접근은 helper를 통해서만 가능하다