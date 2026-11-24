# 13주차 확장 검증 결과 (자동 생성: tests/test_week13.py)

| 입력 | 내용 | 기대 | 보호 전 | 보호 후 | 일치 |
|---|---|---|---|---|---|
| `N_slot1` | 두 번째 가상 함수(slot 1) | 정상(출력 동일) | DERIVED F1 /0 | DERIVED F1 /0 | O |
| `N_slot3` | slot 3 | 정상(출력 동일) | DERIVED F3 /0 | DERIVED F3 /0 | O |
| `N_wide20` | slot 20 (vtable 오프셋 0xa0, 큰 displacement) | 정상(출력 동일) | WIDE W20 /0 | WIDE W20 /0 | O |
| `N_vdtor` | delete 로 가상 소멸자 호출 | 정상(출력 동일) | DERIVED DTOR /0 | DERIVED DTOR /0 | O |
| `N_args` | 인자 5개 가상 호출 (레지스터 보존) | 정상(출력 동일) | SUM6 108642 /0 | SUM6 108642 /0 | O |
| `N_m3_pb` | 부모 3개 다중 상속, 2차 vptr | 정상(출력 동일) | M3 PB b=2 /0 | ID 탐지 /99 [r--p] | **X** |
| `N_m3_pc` | 부모 3개 다중 상속, 3차 vptr | 정상(출력 동일) | M3 PC c=3 /0 | ID 탐지 /99 [r--p] | **X** |
| `N_vd_vl` | 가상 상속(다이아몬드), 1차 부모 | 정상(출력 동일) | VD VL /0 | VD VL /0 | O |
| `N_vd_vr` | 가상 상속, 2차 부모 | 정상(출력 동일) | VD VR /0 | ID 탐지 /99 [r--p] | **X** |
| `N_vd_vb` | 가상 상속, 가상 기반 클래스 포인터 | 정상(출력 동일) | VD VB v=7 /0 | 크래시 sig11 | **X** |
| `N_abstract` | 순수 가상 함수가 있는 추상 클래스 | 정상(출력 동일) | AREA 9 /0 | AREA 9 /0 | O |
| `N_static` | 전역 객체 (상수 초기화 → vptr 이 .data 에 기록됨) | 정상(출력 동일) | DERIVED F0 /0 | ID 탐지 /99 [r--p] | **X** |
| `N_lib_derived` | std::runtime_error 상속 클래스의 what() | 정상(출력 동일) | MYERR WHAT /0 | MYERR WHAT /0 | O |
| `N_lib_object` | libstdc++ 가 만든 예외 객체의 what() (vtable 이 .so 안) | 정상(출력 동일) | LIB WHAT /0 | LIB WHAT /0 | O |
| `N_threads` | 스레드 4개 × 가상 호출 200회 | 정상(출력 동일) | DERIVED F0 /0 | DERIVED F0 /0 | O |
| `N_small_stack` | 스택 64KB 스레드에서 가상 호출 | 정상(출력 동일) | DERIVED F0 /0 | 크래시 sig11 | **X** |
| `N_fd_exhausted` | 파일 디스크립터가 바닥난 상태에서 가상 호출 | 정상(출력 동일) | DERIVED F0 /0 | READONLY 탐지 /99 [unmapped] | **X** |
| `N_many_maps` | mmap 3000개 뒤 가상 호출 (maps > 64KB) | 정상(출력 동일) | DERIVED F0 /0 | DERIVED F0 /0 | O |
| `N_fork` | fork 후 자식·부모 모두 가상 호출 | 정상(출력 동일) | DERIVED F1 /0 | DERIVED F1 /0 | O |
| `K_heap_slot0` | slot 0 호출 | 탐지 READONLY | DERIVED F0 /0 | READONLY 탐지 /99 [rw-p] | O |
| `K_heap_slot1` | slot 1 호출 | 탐지 READONLY | DERIVED F1 /0 | DERIVED F1 /0 | **X** |
| `K_heap_slot3` | slot 3 호출 | 탐지 READONLY | DERIVED F3 /0 | DERIVED F3 /0 | **X** |
| `K_heap_wide20` | slot 20 호출 | 탐지 READONLY | WIDE W20 /0 | WIDE W20 /0 | **X** |
| `K_heap_args` | 인자 5개 호출 | 탐지 READONLY | SUM6 108642 /0 | SUM6 108642 /0 | **X** |
| `K_heap_vdtor` | 가상 소멸자 호출 | 탐지 READONLY | DERIVED DTOR /0 | DERIVED DTOR /0 | **X** |
| `K_heap_m3_pb` | 2차 vptr 호출 | 탐지 READONLY | M3 PB b=2 /0 | READONLY 탐지 /99 [rw-p] | O |
| `K_heap_m3_pc` | 3차 vptr 호출 | 탐지 READONLY | M3 PC c=3 /0 | READONLY 탐지 /99 [rw-p] | O |
| `K_heap_vd_vr` | 가상 상속 2차 vptr 호출 | 탐지 READONLY | VD VR /0 | READONLY 탐지 /99 [rw-p] | O |
| `K_ro_slot0` | 읽기 전용 사본, slot 0 | 탐지 ID | DERIVED F0 /0 | ID 탐지 /99 [r--p] | O |
| `K_ro_slot1` | 읽기 전용 사본, slot 1 | 탐지 ID | DERIVED F1 /0 | DERIVED F1 /0 | **X** |
| `L_reuse` | 다른 클래스의 진짜 vtable 재사용 (원논문 한계) | 탐지 없음(원논문 한계) | BASE F0 /0 | BASE F0 /0 | O |
| `L_mid` | 같은 vtable 안의 다른 위치 (원논문 한계) | 탐지 없음(원논문 한계) | DERIVED F1 /0 | DERIVED F1 /0 | O |
