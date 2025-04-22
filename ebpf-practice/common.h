// 이벤트 구조체 정의

#include <vmlinux.h>
#ifndef __COMMON_H
#define __COMMON_H

struct exec_event {

    u32 pid;
    u32 uid;
    char comm[16];
};

#endif