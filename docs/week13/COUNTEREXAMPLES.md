# 13주차 추가 검증 사례와 반례 목록

> 테스트: `tests/test_week13.py` (대상 `tests/week13/w13_main.cpp`) + 12주차 실패 4건
> 실행: 2026-11-24, Docker `vtint-env` (Ubuntu 22.04, g++ 11.4, LIEF 0.15.1), 기준 코드 `tests` 브랜치 `5afe7af`
> 결과 원본: `docs/results/week13/` (`week13_results.md`, `pytest_week13.txt`, `logs/`)
> 구현 담당용 수정 요청: [`HANDOFF_구현팀.md`](HANDOFF_구현팀.md) (R 번호로 연결)

## 1. 반례를 찾은 방법

**기대 결과는 실행 전에** `tests/test_week13.py`의 `EXPECT` 표에 적고 고정했다. 과제 안내의 6가지 방향에 맞춰 입력을 골랐다.

| 방향 | 우리 구현에서 바꾼 것 | 입력 |
|---|---|---|
| 경계값 | vtable 슬롯 번호 0 → 1 → 3 → 20, 인자 개수, vtsec 크기 4KB 전후 | `N/K_slot*`, `*_wide20`, `*_args`, E5 |
| 표기 변형 | 같은 가상 호출을 다른 기계어 형태로: 다중 상속 2·3차 vptr, 가상 상속, 소멸자, 전역 객체, `-O1/-O2`, PIE | `N_m3_*`, `N_vd_*`, `N_vdtor`, `N_static`, B1~B3 |
| 반복·동시 | 스레드 4개 동시 호출, fork 후 부모·자식 호출 | `N_threads`, `N_fork` |
| 자원 고갈 | 작은 스레드 스택, 파일 디스크립터 고갈, 매핑 수천 개 | `N_small_stack`, `N_fd_exhausted`, `N_many_maps`, C14 |
| 상태 전이 | 라이브러리가 만든 객체, 정적 초기화된 객체 | `N_lib_*`, `N_static` |
| 알려진 한계 | 다른 진짜 vtable 재사용 | `L_reuse`, `L_mid` |

**계측 범위(K) 검사 아이디어**: 객체의 vptr을 진짜 vtable을 **그대로 복사한 사본**으로 바꿔 호출한다. 내용이 같아서 보호 전에는 정상 실행된다. 그 호출 지점에 검사가 붙어 있다면 보호 후에는 반드시 탐지돼야 한다. 공격 함수 없이도 "어떤 형태의 가상 호출이 보호되는가"를 하나씩 확인할 수 있다.

## 2. 반례 목록

분류: **BUG** 구현 버그 / **SCOPE** 명세상 미지원 / **PAPER** 원논문 한계

| 번호 | 입력 | 기대 결과 | 실제 결과 | 분류 | 처리 |
|---|---|---|---|---|---|
| C1 | `N_vd_vb` 가상 상속 객체를 가상 기반 포인터로 호출 | 보호 전·후 `VD VB v=7`, 종료 0 | 보호 후 **SIGSEGV** | BUG | R1 수정 요청 (P0) |
| C2 | `N_small_stack` 스택 64KB 스레드에서 호출 | 출력 동일, 종료 0 | 보호 후 **SIGSEGV** (검사 루틴 스택 64KB 사용) | BUG | R2 (P0) |
| C3 | `N_vdtor`, `N_args` (R6을 시험 수정한 상태) | 출력 동일 | `delete` 지점 **SIGSEGV** (트램펄린이 rax=this를 덮어씀) | BUG (잠재) | R3 (P0), R6과 함께 |
| C4 | `E2_multi_base2`, `N_m3_pb`, `N_m3_pc`, `N_vd_vr` 다중·가상 상속 2·3차 vptr | 탐지 없음, 종료 0 | `ID` 오탐, 종료 99 (vfptr = 원래 `.rodata` 주소) | BUG | R4 |
| C5 | `E5_first`, `E5_all` vtable 201개 (vtsec 20KB) | 탐지 없음 | `ID` 오탐 `vfptr=0x504480` | BUG | R5 |
| C6 | `K_heap_slot1`, `K_heap_slot3`, `K_heap_wide20`, `K_heap_vdtor`, `K_ro_slot1` | READONLY/ID 탐지, 종료 99 | **탐지 없이 실행** (계측 안 됨) | BUG | R6 |
| C7 | `K_heap_args` 인자 5개 가상 호출 | READONLY 탐지 | 탐지 없이 실행 (slot load~call 사이 명령 > 10개) | BUG | R7 |
| C8 | `N_static` 전역 객체 | 탐지 없음 | `ID` 오탐 (vptr이 `.data`에 미리 기록됨, 패치 대상 아님) | BUG | R8 |
| C9 | `C14_big_maps` 매핑 3000개 뒤 정상 vtable | 통과 | `READONLY region=[unmapped]` 오탐 | BUG | R9 |
| C10 | `N_fd_exhausted` fd 고갈 후 호출 | 탐지 없음 | `READONLY region=[unmapped]` 오탐 | BUG | R10 |
| C11 | `N_lib_object` libstdc++ 예외 객체의 `what()` (R6 시험 수정 상태) | 탐지 없음 | `ID` 오탐 (vtable이 libstdc++ 안) | SCOPE → 구현 예정 | R11 (원논문 V-F 페일세이프) |
| C12 | `B1_O1`, `B2_O2` 최적화 빌드 | 검사가 붙거나 도구가 거부 | 도구는 성공(종료 0), `hooked_vcalls: 0` → 보호 없음 | SCOPE (+ 거부 안 하는 것은 BUG) | R12: 거부 처리, 지원은 선택 |
| C13 | `B3_pie_build` PIE 빌드 | 도구가 거부, 또는 정상 동작 | 도구는 성공, 결과 바이너리가 정상 입력에서 SIGSEGV | SCOPE (+ BUG) | R12: PIE면 거부 |
| C14 | `L_reuse` 다른 클래스의 진짜 vtable, `L_mid` 같은 vtable의 다른 칸 | 탐지 없음 (원논문 한계) | 탐지 없음, `BASE F0` / `DERIVED F1` 실행 | PAPER | 한계로 기록, 수정 안 함 |

### 분류 판단 근거
- **C1~C10은 BUG**다. 입력이 모두 우리가 지원한다고 정한 범위(g++ `-O0`, `-no-pie`, x86-64 단일 실행 파일, 11주차 기능 1의 다중 상속 포함)에 있다. 명세("모든 가상 호출 직전 두 검사", "정상 입력 오탐 0건")대로 동작하지 않는다.
- **C6은 12주차 TEST_PLAN에서 [한계]로 적었지만 BUG로 바꿨다.** slot 1 호출은 -O0에서 흔한 형태이고, 원논문 BitCover는 가상 호출 지점을 모두 찾는 것을 목표로 한다. 분석 패턴이 좁은 것은 우리 구현 문제다.
- **C11은 SCOPE**다. 12주차 보고서에서 페일세이프(V-F)를 "다음 주로 넘김"으로 적어 두었다. 원논문은 이 경우를 다루므로 구현 예정 항목으로 넘긴다.
- **C12·C13은 SCOPE**다. 11·12주차에 `-no-pie -O0`만 지원한다고 정했다. 하지만 지원하지 않는 입력을 받고 "성공"이라고 하며 깨진 바이너리를 내는 것은 버그라서 거부 처리를 요청한다.
- **C14는 PAPER**다. 원논문은 vtable 주입·변조를 막는 것이 목표이고, 정상 vtable 재사용은 완전히 막지 못한다고 밝혔다(11주차 보고서 핵심 아이디어 5번 "효과와 한계"). 우리 결과도 같다. 원논문의 해당 절 번호는 보고서에 옮길 때 원문으로 확인한다.

### 잠재 반례 (지금 통과하지만 이유가 잘못된 것)
| 입력 | 지금 통과하는 이유 | R6을 고치면 |
|---|---|---|
| `N_vdtor`, `N_args` | 해당 호출이 계측되지 않아서 | C3 크래시가 드러남 → R3 필요 |
| `N_lib_object` | `e.what()`(slot 2)이 계측되지 않아서 | C11 오탐이 드러남 → R11 필요 |

시험 수정(`bitcover.py`에서 base load와 slot load 사이의 `add` 허용)은 확인용으로만 돌렸고 저장소에는 넣지 않았다.

## 3. 반례가 없었던 사례 (시험한 입력과 근거)

| 입력 | 결과 (보호 전 → 후) | 의미 |
|---|---|---|
| `N_slot1`, `N_slot3`, `N_wide20` | 출력 동일, 종료 0 | 오탐 없음 (단, 계측 안 된 상태라 C6 수정 후 다시 확인) |
| `N_vd_vl` 가상 상속 1차 부모 | 출력 동일 | 1차 vptr은 정상 |
| `N_abstract` 순수 가상 함수 | 출력 동일 | `__cxa_pure_virtual`이 든 vtable도 문제 없음 |
| `N_lib_derived` `runtime_error` 상속 클래스 | 출력 동일 | 실행 파일 안 vtable로 옮겨짐 |
| `N_threads` 4스레드 × 200회 | 출력 동일 | 검사 루틴이 스레드에서 안전 (전역 상태 없음) |
| `N_fork` | 부모·자식 모두 정상 | fork 후에도 vtsec·ID 유지 |
| `N_many_maps` 매핑 3000개 | 정상 | vtsec(0x500000)은 maps 앞쪽이라 잘리지 않음. 매핑된 vtable이 뒤쪽에 있으면 C9 |
| `K_heap_slot0`, `K_ro_slot0` | READONLY / ID 탐지 | slot 0 호출은 두 검사 모두 정상 |
| `K_heap_m3_pb/pc`, `K_heap_vd_vr` | READONLY 탐지 | 2·3차 vptr 호출 지점에도 검사는 붙어 있음 (C4는 오탐 문제일 뿐) |
| 고정 사례 3종 (D), tc1~tc3 (F) | 모두 기대와 일치 | 수정 전 기준선 |

## 4. 숫자 요약
- 전체 99개: 통과 79 / 실패 20 (12주차 64개 중 실패 4 → 새 테스트 35개 추가, 그중 16개 실패)
- 새 반례 14건(C1~C14): BUG 10, SCOPE 3, PAPER 1
- 계측 범위: `w13` 바이너리의 간접 호출 33개 중 계측 18개. K 검사 11개 중 탐지 5개
