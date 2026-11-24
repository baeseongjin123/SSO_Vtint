# 13주차 테스트 요약표 (구현팀 전달용)

> 테스트 코드: `tests/test_week13.py` (35개) / 테스트 프로그램: `tests/week13/` (`w13_main.cpp`, `w13_factory.cpp`, `w13.h`)
> 수정 전 결과: 2026-11-24, Docker `vtint-env`, `docs/results/week13/` 에 저장
> 각 R 항목의 원인·코드 위치·수정 방향: [`HANDOFF_구현팀.md`](HANDOFF_구현팀.md)

## 한눈에 보기
| 묶음 | 개수 | 통과 | 실패 | 확인하는 것 |
|---|---|---|---|---|
| N 정상 입력 | 19 | 12 | **7** | 보호해도 출력이 같고 탐지가 없어야 함 (오탐·크래시) |
| K 계측 범위 | 11 | 5 | **6** | vptr을 진짜 vtable 사본으로 바꿈 → 보호 후 탐지(99)돼야 함 (미탐 = 검사 누락) |
| L 원논문 한계 | 2 | 2 | 0 | 다른 진짜 vtable 재사용 → 탐지 안 되는 게 기대값 |
| B 빌드 옵션 | 3 | 0 | **3** | `-O1`, `-O2`, PIE 입력을 거부하거나 제대로 보호해야 함 |
| **합계** | **35** | **19** | **16** | |

12주차부터 실패하던 4개(`E2_multi_base2`, `E5_first`, `E5_all`, `C14_big_maps`)도 함께 아래 표에 넣었다.

## 실행 방법 (PowerShell, `SSO_Vtint` 폴더에서)
```powershell
# 13주차 35개
docker run --rm --cap-add=SYS_PTRACE --security-opt seccomp=unconfined -v "${PWD}:/work" vtint-env bash -lc "cd /work && python3 -m pytest -q tests/test_week13.py"
# 테스트 하나 (-k 뒤에 테스트 ID)
docker run --rm --cap-add=SYS_PTRACE --security-opt seccomp=unconfined -v "${PWD}:/work" vtint-env bash -lc "cd /work && python3 -m pytest -q tests/test_week13.py -k N_vd_vb"
# 전체 (12주차 포함 99개)
docker run --rm --cap-add=SYS_PTRACE --security-opt seccomp=unconfined -v "${PWD}:/work" vtint-env bash -lc "./test.sh"
```
결과 표는 `results/week13_results.md` 로 자동 생성된다. 결과 표기는 `출력 /종료코드`, `탐지종류 /99 [매핑 권한]`, `크래시 sig11` 이다.

## 1. 실패한 테스트 (고쳐야 할 것) — 20개
우선순위 순서. **"고친 뒤"** 열이 이 테스트가 통과하는 조건이다.

| 우선 | 테스트 ID | 무엇을 확인 | 기대 | 현재 결과 | 관련 | 고친 뒤 |
|---|---|---|---|---|---|---|
| P0 | `N_vd_vb` | 가상 상속, 가상 기반 클래스 포인터로 호출 | `VD VB v=7` /0 | **크래시 sig11** | R1 | 출력 동일, 종료 0 |
| P0 | `N_small_stack` | 스택 64KB 스레드에서 가상 호출 | `DERIVED F0` /0 | **크래시 sig11** | R2 | 출력 동일, 종료 0 |
| P1 | `E2_multi_base2` | 다중 상속 2차 부모 (12주차) | 탐지 없음 | ID 탐지 /99 | R4 | 탐지 없음 |
| P1 | `N_m3_pb` | 부모 3개 다중 상속, 2차 vptr | `M3 PB b=2` /0 | ID 탐지 /99 [r--p] | R4 | 출력 동일, 종료 0 |
| P1 | `N_m3_pc` | 부모 3개 다중 상속, 3차 vptr | `M3 PC c=3` /0 | ID 탐지 /99 [r--p] | R4 | 출력 동일, 종료 0 |
| P1 | `N_vd_vr` | 가상 상속, 2차 부모 | `VD VR` /0 | ID 탐지 /99 [r--p] | R4 | 출력 동일, 종료 0 |
| P1 | `E5_first` | vtable 201개(vtsec 20KB), 첫 클래스 (12주차) | 탐지 없음 | ID 탐지 /99 | R5 | 탐지 없음 |
| P1 | `E5_all` | vtable 201개, 전체 호출 (12주차) | 탐지 없음 | ID 탐지 /99 | R5 | 탐지 없음 |
| P1 | `K_heap_slot1` | slot 1 호출 | READONLY /99 | 탐지 없이 `DERIVED F1` /0 | R6 | READONLY /99 |
| P1 | `K_heap_slot3` | slot 3 호출 | READONLY /99 | 탐지 없이 `DERIVED F3` /0 | R6 | READONLY /99 |
| P1 | `K_heap_wide20` | slot 20 호출 (vtable 오프셋 0xa0) | READONLY /99 | 탐지 없이 `WIDE W20` /0 | R6 | READONLY /99 |
| P1 | `K_heap_vdtor` | 가상 소멸자 호출 (`delete`) | READONLY /99 | 탐지 없이 `DERIVED DTOR` /0 | R6 (+R3) | READONLY /99 |
| P1 | `K_ro_slot1` | 읽기 전용 사본, slot 1 | ID /99 | 탐지 없이 `DERIVED F1` /0 | R6 | ID /99 |
| P1 | `K_heap_args` | 인자 5개 가상 호출 | READONLY /99 | 탐지 없이 `SUM6 108642` /0 | R7 (+R3) | READONLY /99 |
| P1 | `N_static` | 전역 객체 (vptr이 `.data`에 미리 기록됨) | `DERIVED F0` /0 | ID 탐지 /99 [r--p] | R8 | 출력 동일, 종료 0 |
| P1 | `C14_big_maps` | maps 64KB 초과 뒤 정상 vtable (12주차) | 통과 | READONLY /99 [unmapped] | R9 | 통과 |
| P1 | `N_fd_exhausted` | 파일 디스크립터가 바닥난 상태에서 호출 | `DERIVED F0` /0 | READONLY /99 [unmapped] | R10 | 출력 동일, 종료 0 |
| P2 | `B1_O1` | `-O1` 빌드에 VTint 적용 | 검사가 붙거나 도구가 거부 | 도구 성공, `hooked_vcalls: 0` | R12 | 도구가 거부 (또는 지원) |
| P2 | `B2_O2` | `-O2` 빌드에 VTint 적용 | 검사가 붙거나 도구가 거부 | 도구 성공, `hooked_vcalls: 0` | R12 | 도구가 거부 (또는 지원) |
| P2 | `B3_pie_build` | PIE 빌드에 VTint 적용 | 도구가 거부, 또는 정상 동작 | 도구 성공, 결과물이 정상 입력에서 크래시 | R12 | 도구가 거부 |

## 2. 지금 통과하지만 고친 뒤 다시 봐야 하는 테스트
R6(slot 1 이상 계측)을 고치면 지금은 검사가 안 붙어서 통과하던 호출에 검사가 붙는다. 아래 테스트는 **그때 실패로 바뀔 수 있고, 그게 정상**이다. 함께 고칠 항목까지 넣어야 다시 통과한다.

| 테스트 ID | 지금 통과하는 이유 | R6만 고치면 | 같이 고칠 것 |
|---|---|---|---|
| `N_vdtor` | `delete` 호출이 계측 안 됨 | 크래시 (트램펄린이 rax=this 덮어씀, 시험 수정으로 확인) | R3 |
| `N_args` | 인자 많은 호출이 계측 안 됨 | 크래시 가능 (같은 원인) | R3 (+R7) |
| `N_lib_object` | `e.what()`(slot 2)이 계측 안 됨 | ID 오탐 (vtable이 libstdc++ 안, 시험 수정으로 확인) | R11 |
| `N_slot1`, `N_slot3`, `N_wide20` | 계측 안 됨 | 통과해야 함 (오탐이면 새 버그) | — |

## 3. 통과한 테스트 (회귀 확인용) — 19개
고친 뒤에도 **계속 통과해야** 한다.

| 묶음 | 테스트 ID | 무엇을 확인 | 결과 (보호 후) |
|---|---|---|---|
| N | `N_slot1` | slot 1 호출 | `DERIVED F1` /0 (계측 안 된 상태, 2절 참고) |
| N | `N_slot3` | slot 3 호출 | `DERIVED F3` /0 (위와 같음) |
| N | `N_wide20` | slot 20 호출 | `WIDE W20` /0 (위와 같음) |
| N | `N_vdtor` | 가상 소멸자 | `DERIVED DTOR` /0 (2절 참고) |
| N | `N_args` | 인자 5개 | `SUM6 108642` /0 (2절 참고) |
| N | `N_vd_vl` | 가상 상속 1차 부모 | `VD VL` /0 |
| N | `N_abstract` | 추상 클래스 (순수 가상 함수) | `AREA 9` /0 |
| N | `N_lib_derived` | `std::runtime_error` 상속 클래스 | `MYERR WHAT` /0 |
| N | `N_lib_object` | libstdc++ 예외 객체 | `LIB WHAT` /0 (2절 참고) |
| N | `N_threads` | 스레드 4개 × 200회 | `DERIVED F0` /0 |
| N | `N_many_maps` | mmap 3000개 뒤 호출 | `DERIVED F0` /0 |
| N | `N_fork` | fork 후 부모·자식 호출 | `DERIVED F1` /0 |
| K | `K_heap_slot0` | 힙 사본, slot 0 | READONLY /99 [rw-p] |
| K | `K_heap_m3_pb` | 힙 사본, 2차 vptr | READONLY /99 [rw-p] |
| K | `K_heap_m3_pc` | 힙 사본, 3차 vptr | READONLY /99 [rw-p] |
| K | `K_heap_vd_vr` | 힙 사본, 가상 상속 2차 vptr | READONLY /99 [rw-p] |
| K | `K_ro_slot0` | 읽기 전용 사본, slot 0 | ID /99 [r--p] |
| L | `L_reuse` | 다른 클래스의 진짜 vtable 재사용 | 탐지 없음 `BASE F0` /0 (원논문 한계, 고치지 않음) |
| L | `L_mid` | 같은 vtable 안의 다른 칸 | 탐지 없음 `DERIVED F1` /0 (원논문 한계, 고치지 않음) |

고정 사례 3종과 tc1~tc3(12주차 D·F 테스트)도 모두 통과 중이다. 이 테스트들은 입력과 기대값을 바꾸지 않는다.

## 4. R 항목별로 돌릴 테스트
한 항목을 고친 뒤 `-k` 에 아래 문자열을 그대로 넣어 돌리면 된다. 12주차 테스트(E2, E5, C14)도 걸리도록 대상은 `tests/test_week13.py` 가 아니라 `tests` 폴더 전체로 준다. 마지막에는 전체(`./test.sh`)를 한 번 돌린다.

```powershell
docker run --rm --cap-add=SYS_PTRACE --security-opt seccomp=unconfined -v "${PWD}:/work" vtint-env bash -lc "cd /work && python3 -m pytest -q tests -k 'N_vd_vb or N_vd_vl or N_vd_vr'"
```

| R | `-k` 값 |
|---|---|
| R1 | `"N_vd_vb or N_vd_vl or N_vd_vr"` |
| R2 | `"N_small_stack or N_threads"` |
| R3 (R6과 함께) | `"N_vdtor or N_args or K_heap_vdtor or K_heap_args"` |
| R4 | `"E2_multi_base2 or N_m3 or N_vd_vr or K_heap_m3 or K_heap_vd_vr"` |
| R5 | `"E5"` |
| R6 | `"slot or wide20 or vdtor"` |
| R7 | `"args"` |
| R8 | `"N_static"` |
| R9·R10 | `"big_maps or many_maps or fd_exhausted"` |
| R11 | `"N_lib"` |
| R12 | `"B1_O1 or B2_O2 or B3_pie"` |

다 고친 뒤 결과 저장: `bash tests/save_results.sh week13_after` (Docker 안에서 실행).
