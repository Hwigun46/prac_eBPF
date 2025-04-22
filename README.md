# eBPF를 활용한 Monitoring_Sensor 만들기 전 연습

eBPF를 활용하여 Monitoring_Sensor를 만들기 전에 연습 및 학습을 담아둔 Repository입니다.


## 프로젝트 구조
```
ebpf-practice/
├── common.h              # 커널과 유저 영역이 공유하는 구조체
├── exec_monitor.bpf.c    # execve 시스템 콜을 감지하는 eBPF 코드
├── exec_loader.c         # BPF 코드 로드 및 perf buffer 처리
└── Makefile              # 컴파일 설정
docs/
├── new_concept.md        # eBPF 관련 개념 및 배운 용어 정리
├── prac_eBPF_explain.md  # 실습 흐름 설명 (모듈별 분석)
└── sysmon_analysis.md    # Sysmon 구조 분석 및 인사이트
.gitignore
```

## 문서 바로가기
- [연습 흐름 설명](docs/prac_eBPF_explain.md)
- [개념 및 용어 정리](docs/new_concept.md)
- [Sysmon 분석 정리](docs/sysmon_analysis.md)