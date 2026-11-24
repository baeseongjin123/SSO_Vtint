# 13주차 구현 수정 요청서 (테스트 → 구현 담당)

> 작성: 테스트 담당 · 2026-11-24 · 기준 코드: `tests` 브랜치 `5afe7af`
> 반례 전체 목록·분류 근거: [`COUNTEREXAMPLES.md`](COUNTEREXAMPLES.md) · 실행 결과 원본: [`docs/results/week13/`](../results/week13/)

## 0. 한 장 요약

새 테스트(`tests/test_week13.py`, 35개)와 기존 테스트를 합쳐 **99개 중 79개 통과, 20개 실패**.
실패 20개를 원인으로 묶으면 **고칠 것 12개**(아래 표)다. 고정 사례 3종(D)은 지금도 모두 통과한다.

| 우선 | ID | 한 줄 증상 | 고칠 파일 | 확인 테스트 |
|---|---|---|---|---|
| **P0** | R1 | 가상 상속 객체에서 **정상 프로그램이 크래시** | `elfparser.py`, `vrewriter.py` | `N_vd_vb` |
| **P0** | R2 | 스택이 작은 스레드에서 **검사 루틴이 크래시** | `vtint_check.c` | `N_small_stack` |
| **P0** | R3 | 트램펄린이 레지스터를 덮어씀 (R6을 고치면 바로 크래시로 드러남) | `vrewriter.py` | `N_vdtor`, `N_args` |
| P1 | R4 | 2차·3차 vptr 오탐 (다중 상속, 가상 상속) | `elfparser.py`, `vrewriter.py` | `E2_multi_base2`, `N_m3_pb`, `N_m3_pc`, `N_vd_vr` |
| P1 | R5 | vtsec 4KB 초과 시 오탐 (ID가 첫 페이지에만 있음) | `vrewriter.py` | `E5_first`, `E5_all` |
| P1 | R6 | **slot 1 이상 가상 호출은 검사가 안 붙음** (미탐) | `bitcover.py` | `K_heap_slot1/3`, `K_heap_wide20`, `K_heap_vdtor`, `K_ro_slot1` |
| P1 | R7 | 인자가 많은 가상 호출은 검사가 안 붙음 (미탐) | `bitcover.py` | `K_heap_args` |
| P1 | R8 | 전역 객체(상수 초기화)의 vptr을 안 바꿈 → 오탐 | `bitcover.py`, `vrewriter.py` | `N_static` |
| P1 | R9 | `/proc/self/maps` 64KB 초과 시 오탐 | `vtint_check.c` | `C14_big_maps` |
| P1 | R10 | 파일 디스크립터가 바닥나면 오탐 | `vtint_check.c` | `N_fd_exhausted` |
| P1 | R11 | 라이브러리(.so) vtable을 쓰는 호출 오탐 (페일세이프 미구현, R6을 고치면 드러남) | `vtint_check.c` | `N_lib_object` |
| P2 | R12 | PIE·`-O1/-O2` 입력에서 "성공"이라고 하고 깨진 결과를 냄 | `vrewriter.py` / `vtint.py` | `B1_O1`, `B2_O2`, `B3_pie_build` |

**추천 작업 순서**: R12(가드, 10분) → R4+R1(vtable 그룹 파싱) → R5 → R8 → R2+R9+R10(maps 읽기 재작성) → **R6+R3+R7(함께)** → R11.
R6을 고치면 지금은 통과하던 `N_vdtor`(R3)와 `N_lib_object`(R11)가 실패로 바뀐다. 그렇게 되는 게 맞다 (아래 각 항목 참고).

---

## 1. 실행 방법

```powershell
# Windows PowerShell, 저장소 루트에서 (이미지가 있으면 build 생략 가능)
docker build -t vtint-env .
docker run --rm --cap-add=SYS_PTRACE --security-opt seccomp=unconfined -v "${PWD}:/work" vtint-env bash -lc "./test.sh"
```

| 보고 싶은 것 | 명령 (`./test.sh` 뒤에 붙임) |
|---|---|
| 13주차 테스트만 | `-k week13` |
| 특정 항목만 | `-k "N_vd_vb or N_m3_pb"` |
| 고정 사례가 깨지지 않았는지 | `-k D` (항상 통과해야 함) |

결과 표: `results/week13_results.md` (자동 생성) · 로그: `results/logs/G_<모드>_<plain|vtint>.log`

손으로 한 모드만 돌려 보기:
```bash
g++ -std=c++17 -O0 -g -no-pie -fno-pie -fno-stack-protector -U_FORTIFY_SOURCE \
    -fno-devirtualize -fno-devirtualize-speculatively -Wl,-z,relro,-z,now \
    -Itests/week13 -o out/w13_vuln tests/week13/w13_factory.cpp tests/week13/w13_main.cpp
python3 tools/vrewriter.py out/w13_vuln out/w13_hardened
./out/w13_vuln N_vd_vb ; echo $?      # 보호 전
./out/w13_hardened N_vd_vb ; echo $?  # 보호 후
```

### 테스트 프로그램 읽는 법 (`tests/week13/w13_main.cpp`)
| 접두어 | 뜻 | 보호 후 기대 |
|---|---|---|
| `N_` | 정상 입력 | 보호 전과 출력이 같고 `VTINT DETECTED` 없음, 종료 0 |
| `K_` | **계측 범위 검사**. 객체의 vptr을 진짜 vtable을 그대로 복사한 사본으로 바꿔서 호출한다. 내용이 같으니 보호 전에는 정상 실행되고, 그 호출 지점에 검사가 붙어 있다면 보호 후에는 반드시 탐지돼야 한다 | `K_heap_*` → READONLY/99, `K_ro_*` → ID/99 |
| `L_` | 원논문 한계 (다른 진짜 vtable 재사용) | 탐지 없음. 고치지 않는다 |

---

## 2. 항목별 상세

### R1 [P0] 가상 상속에서 정상 프로그램 크래시 — `N_vd_vb`
- **증상**: `VB* b = make_vd(); b->vb();` → 보호 전 `VD VB v=7`, 보호 후 **SIGSEGV**.
- **원인**: 가상 상속 vtable은 offset-to-top **앞쪽**에 vbase offset·vcall offset 칸이 더 있다.
  `elfparser.py:94`가 offset-to-top == 0 인 곳부터 테이블을 잘라서 그 앞 칸이 vtsec으로 복사되지 않는다.
  실측: `_ZTV2VD`는 0x405198에서 시작하는데 후보는 0x4051a0부터 잡혀서 8바이트가 빠졌다.
  vtsec에서는 그 자리에 앞 테이블(Square)의 함수 포인터가 오고, VD→VB 변환이 이 값을 vbase offset으로 읽는다.
  그 결과 엉뚱한 포인터가 나와 트램펄린의 base load에서 죽는다.
  VTT(`_ZTT2VD`)와 construction vtable(`_ZTC...`)도 코드 immediate가 아니라 데이터로 참조되므로 지금은 패치되지 않는다.
- **수정 방향**:
  1. 심볼이 있으면 `_ZTV*`, `_ZTC*`의 `st_size`로 **그룹 전체**(앞쪽 칸 포함)를 한 덩어리로 복사한다.
  2. 그룹 안의 주소점을 모두 새 주소로 매핑한다(R4와 같은 작업).
  3. VTT 안의 vtable 주소(8바이트 데이터)도 새 주소로 바꾼다(R8의 데이터 패치를 같이 쓰면 된다).
- **확인**: `N_vd_vb`, `N_vd_vr`, `N_vd_vl`, `K_heap_vd_vr`가 모두 통과해야 한다.

### R2 [P0] 작은 스택에서 검사 루틴 크래시 — `N_small_stack`
- **증상**: 스택 64KB 스레드에서 가상 호출 → 보호 후 SIGSEGV (`orq $0x0,(%rsp)`, 스택 프로빙 지점).
- **원인**: `vtint_check.c:95` `char buf[65536];` — 검사 한 번에 스택 64KB를 쓴다. 스레드 스택, 시그널 대체 스택처럼 작은 곳에서 넘친다.
- **수정 방향**: R9와 묶어서 **작은 버퍼(예: 4KB)로 반복 읽기 + 줄 단위 처리**로 바꾼다. 줄이 버퍼 끝에서 잘리면 남은 조각을 앞으로 옮겨 이어 붙인다. 대상 주소를 찾으면 바로 중단한다.
- **확인**: `N_small_stack`, `C14_big_maps`, `N_many_maps`.

### R3 [P0] 트램펄린이 caller-saved 레지스터를 덮어씀 — `N_vdtor`, `N_args`
- **지금 상태**: 테스트는 통과한다. 하지만 R6 때문에 **해당 호출이 계측되지 않아서** 통과하는 것뿐이다.
- **증거 (R6 수정을 시험 삼아 넣어 본 결과)**: `delete p` 지점이 계측되자 보호 후 **SIGSEGV**가 났다. 그 지점의 원래 코드는 다음과 같다.
  ```
  mov (%rax),%rdx      ; base load (base = rdx)
  add $0x30,%rdx
  mov (%rdx),%rdx      ; slot load
  mov %rax,%rdi        ; ← rax(=객체 포인터)를 윈도우 뒤에서 다시 씀
  call *%rdx
  ```
  트램펄린(`vrewriter.py:88` `build_trampoline`)은 base 레지스터만 저장한다.
  그런데 `movabs rax,&check; call rax`와 C 함수 `__vtint_check`가 rax, rcx, rdx, rsi, rdi, r8~r11을 덮어쓴다.
  그래서 `this`가 망가진다.
  slot 0이고 base가 rax인 지금 예제들은 우연히 괜찮았다.
- **수정 방향**: 트램펄린에서 `pushfq` 후 rax, rcx, rdx, rsi, rdi, r8~r11을 모두 저장하고 호출 뒤 복원한다. push 개수로 16바이트 정렬도 맞춘다.
- **확인**: R6 수정 후 `N_vdtor`, `N_args`, `K_heap_vdtor`, `K_heap_args`가 모두 통과해야 한다.

### R4 [P1] 2차·3차 vptr 오탐 — `E2_multi_base2`, `N_m3_pb`, `N_m3_pc`, `N_vd_vr`
- **증상**: `PB* b = make_m3(); b->pb();` → `VTINT DETECTED ID vfptr=0x4054a8 region=[r--p]` (원래 `.rodata` 주소).
- **원인**: `_ZTV2M3`은 vtable 그룹이다 (`[0][ti][PA 쪽…][-16][ti][PB 쪽…][-32][ti][PC 쪽…]`).
  `elfparser.py:94`가 offset-to-top ≠ 0 인 곳을 건너뛰어 1차 부분만 후보가 된다.
  생성자의 `mov $0x4054a8,%edx`(2차 주소점)는 후보 목록에 없어서 패치되지 않는다.
  실측 Multi 생성자: `mov $0x402060` → 패치됨, `mov $0x402090` → 패치 안 됨.
- **수정 방향**: 그룹 파싱을 바꾼다. 한 테이블이 끝난 뒤 바로 `[음수 offset-to-top][같은 typeinfo][코드 포인터…]`가 오면 같은 그룹으로 묶는다(심볼 크기를 쓰면 더 간단하다). 그룹 안의 **모든** 주소점을 `newpoint`(`vrewriter.py:135~`)에 넣는다.
- **확인**: 위 4개 테스트 + `K_heap_m3_pb/pc`(지금도 통과, 계속 통과해야 함).

### R5 [P1] vtsec 4KB 초과 오탐 — `E5_first`, `E5_all`
- **증상**: vtable 201개. `Big<0>`이 0x504470으로 가서 `VTINT DETECTED ID vfptr=0x504480`이 난다.
- **원인**: `vrewriter.py:140`에서 ID를 vtsec 맨 앞에 **한 번만** 쓴다. 검사는 vfptr이 속한 4KB 페이지의 선두를 읽는다. 154개 vtable이 둘째 페이지 이후에 있었다. 원논문은 페이지마다 ID를 둔다.
  (`last`가 통과한 것은 배치 순서가 거꾸로라 `Big<199>`가 맨 앞에 왔기 때문이다.)
- **수정 방향**: vtable을 이어 붙이다가 다음 테이블이 4KB 경계를 넘으면 다음 페이지로 패딩하고 그 페이지 선두 8바이트에 ID를 다시 쓴다. 테이블이 페이지에 걸치지 않게 배치한다.
- **확인**: `E5_first/last/all` + 기존 `A12`(있다면).

### R6 [P1] slot 1 이상은 검사 미삽입 (미탐) — `K_heap_slot1/3`, `K_heap_wide20`, `K_heap_vdtor`, `K_ro_slot1`
- **증상**: 사본 vtable로 바꿔도 slot 0만 탐지되고 slot 1·3·20과 소멸자 호출은 그냥 실행된다.
  **같은 공격이 slot 1 함수를 노리면 막지 못한다는 뜻이다** (12주차 tc3에서 이미 관찰).
- **원인**: g++ -O0의 slot k≥1 호출은 `mov (%rax),%rax; add $0x8*k,%rax; mov (%rax),%rdx` 형태다. `bitcover.py:91`은 slot load **바로 앞**이 base load여야만 인식한다.
- **분류 변경**: 12주차 TEST_PLAN에서는 [한계]로 적었다. 하지만 -O0 / no-PIE는 우리가 지원한다고 정한 범위이고, 명세는 "모든 가상 호출 직전 검사"다. 그래서 **구현 버그**로 다시 분류했다.
- **수정 방향**: base load와 slot load 사이의 `add <base>, imm`을 허용한다. 트램펄린의 slot 부분에 `add` 바이트도 같이 넣는다. 시험 삼아 넣어 보니 slot 1·3·20·소멸자가 모두 READONLY/ID로 탐지됐다.
  **반드시 R3와 같이 고친다** (안 그러면 `N_vdtor`가 크래시).
- **확인**: 위 K 테스트 전부 + N 테스트 전부.

### R7 [P1] 인자가 많은 호출 미계측 — `K_heap_args`
- **원인**: `bitcover.py:74`가 call에서 거꾸로 **최대 10개 명령**까지만 slot load를 찾는다. 인자 5개 호출은 slot load(`mov (%rax),%r10`)와 `call *%r10` 사이에 인자 계산 명령이 10개를 넘는다.
- **수정 방향**: 탐색 범위를 늘린다(예: 64개 또는 기본 블록 시작까지). 대신 그 사이에 slot 레지스터를 덮어쓰는 명령이 없는지 지금처럼 확인한다.

### R8 [P1] 전역 객체의 vptr 미패치 — `N_static`
- **증상**: `Derived g_static_derived;` → `VTINT DETECTED ID vfptr=0x405638`.
- **원인**: 생성자가 상수식이라 g++가 객체를 **`.data`에 이미 vptr이 채워진 상태로** 넣는다. 실행 중 생성자 호출이 없다(정적 초기화 코드에는 `__cxa_atexit` 등록만 있다). 지금 구현은 코드 안의 immediate만 패치해서 데이터 속 vtable 주소를 놓친다. 원논문은 relocation 정보로 이런 참조까지 찾는다.
- **수정 방향**: `.data`, `.data.rel.ro`, VTT 등 데이터 섹션에서 8바이트 정렬 값이 **확정 vtable의 주소점과 같은 곳**을 찾아 새 주소로 패치한다. 심볼 범위로 잘못 맞는 경우를 걸러낸다.

### R9 [P1] maps 64KB 초과 오탐 — `C14_big_maps`
- 원인·수정: R2와 같다(반복 읽기). 현재는 64KB에서 잘려 `region=[unmapped]` → READONLY로 탈락한다.

### R10 [P1] 파일 디스크립터 고갈 시 오탐 — `N_fd_exhausted`
- **증상**: `RLIMIT_NOFILE`를 다 쓴 상태에서 정상 호출 → `READONLY region=[unmapped]`.
- **원인**: `vtint_check.c:96` `open` 실패 → maps 내용 0바이트 → 매핑 없음 → `:132` 안전 쪽 탈락. 같은 일이 `/proc`이 없는 환경(chroot, 샌드박스)에서도 생긴다.
- **수정 방향 (둘 다 권장)**:
  1. **빠른 경로**: vfptr이 `[VTSEC_VA, VTSEC_END)` 안이면 READONLY 검사를 건너뛰고 ID만 본다. vtsec은 우리가 R 권한으로 만든 세그먼트라 쓰기 불가가 보장된다. 호출마다 maps를 읽는 비용도 크게 줄어 14주차 성능 실험에도 좋다.
  2. open 실패 시 정책을 정해 README에 적는다(예: vtsec 밖이면 탈락 유지).

### R11 [P1] 라이브러리 vtable 오탐 (페일세이프) — `N_lib_object`
- **지금 상태**: 통과한다. 하지만 `e.what()`이 slot 2 호출이라 R6 때문에 계측되지 않았을 뿐이다.
- **증거**: R6 수정을 시험 삼아 넣자 `VTINT DETECTED ID vfptr=0x7c5476bc7318 region=[r--p]`가 났다(libstdc++ 안의 vtable).
- **원인**: 원논문 V-F의 "보호되지 않은 모듈에서 온 vtable은 통과" 규칙이 없다(12주차 보고서에서 미구현으로 적은 부분).
- **수정 방향**: maps 줄의 마지막 칸(경로)을 함께 파싱한다. vfptr이 **주 실행 파일이 아닌 파일 매핑**(`.so`)이면 통과시킨다. 익명·힙 매핑은 지금처럼 검사한다.
- **확인**: R6 수정 후 `N_lib_object`가 통과해야 한다. `N_lib_derived`도 계속 통과해야 한다.

### R12 [P2] 지원하지 않는 입력을 조용히 망가뜨림 — `B1_O1`, `B2_O2`, `B3_pie_build`
- **증상**:
  - `-O1/-O2`: 가상 호출이 전부 `call *0x8(%rax)` 같은 메모리 간접 호출이라 `hooked_vcalls: 0`. 그런데도 도구는 성공(종료 0)이라고 하고, 결과 바이너리에는 검사가 하나도 없다.
  - PIE: `moved_vtables: []`인데 18곳을 트램펄린으로 바꾼다. 결과 바이너리는 **정상 입력에서도 SIGSEGV**.
- **수정 방향 (최소)**: `ELFParser.is_pie`(`elfparser.py:32`)가 참이면 오류로 종료한다. `call [reg+disp]`가 있는데 `hooked_vcalls == 0`이면 경고 후 실패로 끝낸다. 테스트는 도구가 **명시적으로 거부하면 skip(허용)** 처리하게 짜 두었다.
- **수정 방향 (선택)**: `call qword ptr [base+disp]` 패턴 지원 → 14주차 "최적화 수준" 실험이 가능해진다.

---

## 3. 고치지 않는 것 (원논문 한계) — `L_reuse`, `L_mid`
vptr을 **다른 진짜 vtable**(다른 클래스, 또는 같은 테이블의 다른 칸)로 바꾸면 READONLY·ID 검사를 모두 통과한다. 원논문도 vtable 재사용은 완전히 막지 못한다고 밝혔다. 테스트는 "탐지 없음"을 기대값으로 두고 한계가 그대로 재현되는지만 기록한다.

## 4. 수정 후 할 일
1. `./test.sh` 전체 실행 → 통과 수와 `results/week13_results.md`를 보내 주면 수정 전·후 비교표를 보고서에 넣는다.
2. 고정 사례 3종(`-k D`)은 수정 후에도 그대로 통과해야 한다(입력·기대값 변경 금지).
3. 결과 저장: `bash tests/save_results.sh week13_after` (수정 전 결과는 `docs/results/week13/`에 있음).
