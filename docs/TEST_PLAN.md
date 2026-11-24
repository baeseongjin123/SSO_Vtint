# VTint 테스트 계획 및 1차 결과 (12주차)

> 대상: `VTint` 브랜치의 바이너리 재작성 구현 (ELFParser → BitCover → VRewriter).
> 과제 전체 정리와 11주차 계획 대비 차이: `docs/PROJECT_OVERVIEW.md` (3.5절).
> 도구: **pytest**. 실행: `./docker-test.sh` (Docker) 또는 `./test.sh` (리눅스).

## 0. 목표
1. 11주차 고정 검증 사례 3종이 기대 결과와 **보호 전·후 모두** 일치하는지 자동 확인
2. 판정 기준을 출력 문자열·종료 코드·주소 수준으로 구체화 (12주차 피드백)
3. 다중 상속 포함 정상 입력에서 **오탐 0건** 확인 (성공 기준)
4. 재작성 결과물이 VTint 전제(vtsec 읽기 전용, ID, 계측)를 만족하는지 확인 (조교 피드백 반영)
5. 실행 로그와 전·후 비교표를 자동으로 남겨 보고서·재현 증거로 사용

## 1. 구현과의 인터페이스 (실제 코드 기준)

| 항목 | 값 |
|---|---|
| 보호 전 바이너리 | `out/victim_vuln` (`tests/build.sh`, g++ `-O0 -no-pie`, full RELRO) |
| 보호 후 바이너리 | `out/victim_hardened` (`tools/vrewriter.py out/victim_vuln out/victim_hardened`) |
| 입력 | `argv[1]` = `normal` / `inject` / `rodata` |
| 정상 / 탈취 출력 | stdout `DERIVED RUN` (0) / `HIJACKED` (66) |
| 탐지 출력 | stderr `VTINT DETECTED <READONLY\|ID> vfptr=0x<16자리> region=[perms]` (99). 매핑이 없으면 `region=[unmapped]` |
| 유출 주소 | stdout `[leak] fake vtable @ 0x...`, `[leak] rodata fptr array @ 0x...` |
| 재작성 메타데이터 | vrewriter 의 JSON 출력: `id`, `vtsec_va`(0x500000), `code_va`(0x600000), `moved_vtables`, `hooked_vcalls`, `patched_refs` |

테스트는 세션 시작 시 `build.sh` + `vrewriter.py`를 한 번 실행해 바이너리를 새로 만들고, 메타데이터를 `out/pipeline_meta.json`에 저장한다. `VTINT_NO_BUILD=1`이면 이미 있는 `out/` 바이너리를 쓴다.

## 2. 테스트 구성

```
A 재작성 결과물 (정적)  ─┐
B 실행 중 메모리 맵     ─┼─ VTint 가 성립하는 전제인가
C 검사 루틴 단위        ─┘  검사 함수 하나가 맞게 판정하는가
D 고정 3종 E2E          ── 과제의 핵심 판정 (수정 금지 사례)
E 오탐 묶음             ── 성공 기준 "오탐 0건" (VTint 를 다른 입력 바이너리에도 적용)
```

### A. 재작성 결과물 — `tests/test_build.py`
| ID | 검사 | 기대 |
|---|---|---|
| A1 | 보호 바이너리 ELF 타입 | `EXEC` (no-PIE) |
| A2 | full RELRO 유지 | `GNU_RELRO` + `BIND_NOW` |
| A3·A4 | vtsec 세그먼트 | `vtsec_va`에 LOAD 세그먼트, 4KB 정렬 |
| A5 | vtsec 권한 | `R`만 |
| A6 | 검사 코드 세그먼트 | `R E` (W 없음) |
| A7 | 이전된 vtable | 모두 vtsec 안, 내용이 원본 `.rodata` vtable과 같음 |
| A7b | 이전 대상 | Base, Derived 포함 |
| A8 | ID 공간 확보 (조교 피드백) | 첫 vtable 주소 ≥ vtsec + 8 |
| A9 | ID 기록 | vtsec 첫 8바이트 = 메타데이터 ID, 0 아님 |
| A10 | 재작성마다 무작위 ID | 같은 입력을 두 번 재작성하면 ID가 다름 |
| A11 | 보호 전 바이너리 | vtsec 주소에 세그먼트 없음 |
| A12 | vtable이 놓인 모든 4KB 페이지 | 페이지 선두 8바이트 = ID |
| A13 | 계측 | 가상 호출 계측 ≥ 1, vtable 참조 패치 ≥ 1 |

### B. 실행 중 메모리 맵 — `tests/test_build.py` (gdb)
| ID | 시점 | 기대 |
|---|---|---|
| B1 | `normal`, `Derived::run` 진입 | vtsec 페이지가 `r--p` (조교 피드백) |
| B2 | 같음 | 검사 코드 페이지가 `r-xp` |
| B3 | `inject`, 검사 루틴의 exit syscall | 가짜 vtable 주소가 `rw-p` (위반 사례의 전제) |
| B4 | `rodata`, 같음 | `.rodata` 배열 주소가 `r--p` (경계 사례의 전제) |

Docker에서는 `--cap-add=SYS_PTRACE --security-opt seccomp=unconfined`가 필요하다 (`docker-test.sh`에 들어 있음). gdb를 못 쓰면 skip.

### C. 검사 루틴 단위 — `tests/test_runtime_unit.py` + `tests/unit/check_harness.c`
`runtime/vtint_check.c`를 VRewriter와 같은 옵션·고정 ID로 컴파일해 하네스와 링크하고, 케이스마다 subprocess로 실행한다. 판정: 종료 코드 + 탐지 종류 + 탐지 vfptr == 넘긴 주소.

| ID | 넘기는 주소 | 기대 |
|---|---|---|
| C1 | 읽기 전용 페이지 + 선두 ID | 통과 |
| C2 | 같은 페이지 끝 | 통과 |
| C3 | 힙 | READONLY |
| C4 | 스택 | READONLY |
| C5 | 쓰기 가능 전역(.data) | READONLY |
| C6 | `.rodata` const 함수 포인터 배열 | ID |
| C7 | 코드(r-x) | ID |
| C8 | NULL | 크래시 없이 READONLY (unmapped) |
| C9 | 매핑 해제된 주소 | READONLY |
| C10 | 쓰기 가능 페이지 + 선두 ID (ID 유출 가정) | READONLY |
| C11 | 읽기 전용 + 틀린 ID | ID |
| C12 | r-x 페이지 + 선두 ID | 통과 (쓰기 불가 + ID 일치면 통과하는 정책 확인) |
| C13 | 2페이지 읽기 전용, ID는 첫 페이지만, 둘째 페이지 주소 | ID (검사는 페이지 선두만 봄 → 재작성기가 페이지마다 ID를 써야 함) |
| C14 | `/proc/self/maps`가 64KB를 넘을 때의 정상 vtable 페이지 | 통과 |

### D. 고정 검증 사례 3종 — `tests/test_fixed_cases.py`
기대 결과는 `tests/fixed/fixed_cases.json`(11주차 보고서 원문)에서 읽는다.

| ID | 입력 | 바이너리 | 판정 기준 (모두 만족) |
|---|---|---|---|
| D1·D2 | `normal` | 보호 전·후 | 종료 0 · `DERIVED RUN` · `VTINT DETECTED`/`HIJACKED` 없음 |
| D3 | `inject` | 보호 전 | 종료 66 · `HIJACKED` |
| D4 | `inject` | 보호 후 | 종료 99 · `READONLY` · region이 쓰기 가능 · vfptr == 유출된 가짜 vtable 주소 · `HIJACKED` 없음 |
| D5 | `rodata` | 보호 전 | 종료 66 · `HIJACKED` |
| D6 | `rodata` | 보호 후 | 종료 99 · 탐지가 `ID` 한 줄뿐(READONLY 통과) · region `r--p` · vfptr == 유출된 rodata 주소 · `HIJACKED` 없음 |
| D7 | 고정 사례 파일 | — | `fixed_cases.json`의 SHA-256 == `tests/fixed/SHA256SUMS` |

각 사례를 5회 반복해 판정이 같아야 하고(ASLR 켠 상태), 시그널 종료·시간 초과는 실패로 본다.

### E. 오탐 0건 — `tests/test_false_positive.py`
victim에는 Base/Derived만 있으므로 11주차 기능 1 구성을 담은 정상 프로그램(`tests/progs`)을 `build.sh`와 같은 옵션으로 컴파일 → VRewriter로 재작성한 뒤, 보호 전·후 출력이 같고 탐지가 없는지 본다.

| ID | 프로그램·입력 | 기대 |
|---|---|---|
| E1 | `fp_main` base / derived / other | 종료 0, 탐지 없음, 출력 동일 |
| E2 | `fp_main` multi / multi_base2 (다중 상속, 2차 vptr) | 같음 |
| E3 | `fp_main` repeat (가상 호출 1000회) | 같음 |
| E4 | victim `normal` | 같음 |
| E5 | `fp_many` first / last / all (vtable 200개, vtsec 약 16KB) | 같음 |

### F. 직접 작성한 테스트케이스 프로그램 3종 — `tests/test_cases.py` + `tests/cases/`
팀원 victim 과 같은 인터페이스를 따르는 취약 대상 프로그램을 직접 작성해(`tests/cases/`), 한 프로그램에서 모드(`normal`/`inject`/`rodata`)로 세 사례를 모두 재현한다. 각 프로그램을 build.sh 옵션으로 컴파일 → VRewriter 재작성 → 보호 전·후로 실행해 D와 같은 기준으로 판정한다.

| 프로그램 | 특징 (서로 다른 각도) | 3사례 결과 |
|---|---|---|
| tc1 | 단일 상속, **스택** 객체, slot 0 | 정상·위반·경계 모두 기대 일치 |
| tc2 | 단일 상속, **힙** 객체, slot 0 (객체 위치 무관하게 탐지되는지) | 모두 일치 |
| tc3 | **다단계 상속**(A→B→C), slot 0 (가장 깊은 vtable 도 보호되는지) | 모두 일치 |

각 프로그램마다 정상(전·후), 위반(전·후), 경계(전·후) 6번씩 실행하며, 위반은 READONLY·경계는 ID 로 걸리는지와 탐지 vfptr 이 유출 주소와 같은지까지 본다.

> **왜 slot 1 프로그램은 넣지 않았나 (13주차 반례로 분리):** 처음엔 tc3 을 "두 번째 가상 함수(slot 1) 호출"로 만들었는데, 보호 후에도 공격이 그대로 성공했다(HIJACKED/66). 원인은 구현이 아니라 **BitCover 의 가상 호출 탐지 한계**다. g++ -O0 는 slot 0 호출을 `mov (%rax),%rax; mov (%rax),%rdx`(붙어 있는 쌍)로 내지만, slot 1 호출은 중간에 `add $0x8,%rax` 가 끼어 `mov (%rax),%rax; add $0x8,%rax; mov (%rax),%rdx` 가 된다. `bitcover.py` 의 `_match_vcall` 은 base 로드 **바로 다음**에 slot 로드가 와야 인식하므로(`prev = insns[k-1]`), slot 1 이상은 탐지에서 빠져 계측되지 않는다. → **구현 한계 [한계]**. 13주차에 slot 1 프로그램을 반례로 제출하고, 수정안(윈도우 탐색 시 사이의 `add r, imm` 를 허용)을 제안한다.

## 3. 1차 실행 결과 (2026-11-22, Docker Ubuntu 22.04)

**63개 중 59개 통과, 4개 실패.** 고정 사례 3종(D)과 직접 만든 3종(F)은 모두 기대와 일치. 실패 4건은 아래 표의 구현 문제뿐이다.

| 구분 | 입력 | 보호 전 | 보호 후 | 기대 일치 |
|---|---|---|---|---|
| 정상 | `normal` | 정상 종료 / exit 0 | 정상 종료 / exit 0 | O |
| 위반 | `inject` | 제어 흐름 탈취 / exit 66 | 탐지 후 차단 (READONLY) / exit 99 | O |
| 경계 | `rodata` | 제어 흐름 탈취 / exit 66 | 탐지 후 차단 (ID) / exit 99 | O |

실패한 4개는 테스트 오류가 아니라 **구현에서 찾은 문제**다. 기대값은 바꾸지 않고 원인을 기록한다.

| 테스트 | 증상 | 원인 (분석) | 분류 |
|---|---|---|---|
| E2 `multi_base2` | 정상 호출인데 `VTINT DETECTED ID vfptr=0x402090 region=[r--p]` | 다중 상속 객체의 **2차 vptr**(Second 쪽, vtable+N 주소점)을 생성자 패치에서 빠뜨림. `vrewriter.py`의 `newpoint`가 vtable마다 1차 주소점만 매핑해서, 2차 vptr이 원래 `.rodata` vtable을 계속 가리킴 → 그 페이지엔 ID가 없음 | 구현 버그 |
| E5 `first`, `all` | `VTINT DETECTED ID vfptr=0x504480` (vtsec 안의 진짜 vtable) | vtsec이 4KB를 넘는데 **ID를 첫 페이지(0x500000)에만** 씀. 검사는 vfptr의 페이지 선두(0x504000)를 읽으므로 둘째 페이지부터 오탐. 원논문은 페이지마다 ID를 둠 (A12와 같은 위험) | 구현 버그 |
| C14 `big_maps` | 정상 vtable 페이지인데 `VTINT DETECTED READONLY region=[unmapped]` | 검사 루틴이 `/proc/self/maps`를 64KB 버퍼까지만 읽음. 매핑이 수천 개면 뒤쪽이 잘려 "매핑 없음"으로 판정 | 구현 한계 (13주차 반례 후보) |

수정 제안 (구현 담당과 상의):
- 2차 vptr: vtable 그룹 안의 모든 주소점(`offset-to-top` 위치마다)을 `newpoint`에 넣어 패치
- 페이지 ID: vtable을 옮길 때 4KB 경계를 넘으면 다음 페이지 선두에 ID를 다시 쓰고 vtable이 페이지를 걸치지 않게 배치
- maps: 버퍼를 끝까지 읽으며 줄 단위로 처리(버퍼 재사용), 또는 대상 주소를 찾으면 바로 중단

## 4. 파일 구성과 실행 방법
```
test.sh / docker-test.sh   # 실행 스크립트
pytest.ini
tests/
  conftest.py              # 빌드·재작성 fixture, run 헬퍼, 출력 파싱, 로그·비교표 생성
  test_build.py            # A, B
  test_runtime_unit.py     # C
  test_fixed_cases.py      # D
  test_false_positive.py   # E
  test_cases.py            # F (직접 만든 테스트케이스 3종)
  cases/                   # F 대상 프로그램 (tc1/tc2/tc3, 각 .h + _factory.cpp + _main.cpp)
  unit/check_harness.c     # C 하네스
  progs/                   # E 정상 프로그램 (fp_main, fp_many)
  fixed/                   # 고정 사례 — 수정 금지
    fixed_cases.json  SHA256SUMS
results/                   # 자동 생성: before_after.md, env.txt, logs/ (git 제외, 실행마다 바뀜)
docs/results/<이름>/       # 제출용 결과 (tests/save_results.sh 로 저장, 이것만 커밋)
```

| 명령 | 하는 일 |
|---|---|
| `./docker-test.sh` | 이미지 빌드 후 컨테이너에서 전체 테스트 |
| `./docker-test.sh -k D` | 고정 사례만 |
| `./test.sh` | 리눅스에서 바로 실행 (pyelftools, capstone, lief, pytest, gdb 필요) |
| `VTINT_NO_BUILD=1 ./test.sh` | 다시 빌드하지 않고 `out/` 바이너리로 실행 |

Dockerfile에는 테스트용으로 `gdb`, `pytest`만 추가했다.

## 5. 남은 일 (12주차)
1. 실패 4건을 구현 담당에게 전달하고, 고친 뒤 다시 실행
2. 다른 팀원 PC에서 `./docker-test.sh` 재실행 → `results/before_after.md`를 비교하고 재현 메모 작성
3. 12주차 결과는 `docs/results/week12/`에 저장해 둠 → 보고서 "첫 실행 및 비교 결과"에 `before_after.md` 첨부

## 6. 13주차 후보
> **13주차 결과 (2026-11-24)**: 아래 후보를 포함해 35개 테스트를 `tests/test_week13.py`로 추가했다 → 반례 14건. 목록·분류는 `docs/week13/COUNTEREXAMPLES.md`, 구현 수정 요청은 `docs/week13/HANDOFF_구현팀.md`.
> slot 1 가상 호출은 [한계]에서 **구현 버그**로 다시 분류했다 (지원 범위인 -O0에서 생기는 문제라서).

분류: **[버그]** 구현 버그 / **[한계]** 명세상 미지원·원논문 한계

| 후보 | 입력 아이디어 | 예상 결과 | 예상 분류 |
|---|---|---|---|
| vtable 재사용 | vfptr을 다른 클래스의 진짜 vtable(vtsec 안)로 덮기 | 탐지 못 함 | [한계] 원논문도 완전 차단 불가 |
| vtable 중간 주소 | vfptr = 진짜 vtable + 8 | 탐지 못 함 | [한계] |
| ID 위치 자체 | vfptr = vtsec 시작 | 통과 | [한계] |
| UAF | 해제 후 같은 크기 할당으로 vfptr 덮기 | 탐지 | 미탐 시 [버그] |
| libc `.rodata` | libc의 `r--p` 영역 주소로 덮기 | ID로 탐지 | 미탐 시 [버그] |
| `-O2` 컴파일 | 다른 가상 호출 패턴 | 계측 누락 가능 | [한계] (BitCover 패턴 의존) |
| 2차 vptr 덮기 | Multi의 Second 쪽 vptr을 오버플로 | 탐지 | E2 버그 수정 후 확인 |
| **slot 1 가상 호출** | 두 번째 가상 함수 호출(`add $0x8` 끼는 코드) | 보호 후에도 HIJACKED (계측 누락) | [한계] BitCover 패턴이 slot 0 만 인식 (2절 F 참고) |
| maps 64KB 초과 | C14 | 오탐 | [한계] → 수정 가능 |
| 검사-호출 사이 경쟁 | 검사 후 다른 스레드가 vfptr 변경 (TOCTOU) | 탐지 못 함 | [한계] |

### 14주차 실험 변수 후보 (변수 하나 바꾼 실험)
- 가상 호출 횟수(10³~10⁷)에 따른 실행 시간: 보호 전 vs 보호 후 → 원논문 "2% 미만"과 비교 (현재 구현은 호출마다 `/proc/self/maps`를 읽어 훨씬 느릴 것으로 예상)
- 검사 방식: maps 매번 읽기 vs 결과 캐시
