# VTint (ELF 적응) 아키텍처 · 원리 상세

## 0. 한눈에

```
 컴파일된 exe                                                   보호 바이너리
 (victim_vuln)                                                 (victim_hardened)
      │                                                              ▲
      ▼                                                              │
 ┌──────────────┐    후보 vtable    ┌──────────────┐  호출/참조  ┌──────────────┐
 │ ① ELFParser  │ ───────────────▶ │ ② BitCover   │ ─────────▶ │ ③ VRewriter  │
 │  (PEParser)  │                   │  디스어셈블   │            │  바이너리재작성 │
 └──────────────┘                   └──────────────┘            └──────────────┘
    pyelftools                         capstone                  LIEF + 검사루틴
```

---

## 1. 배경: 가상 함수 호출과 vtable hijacking

C++ 다형성 객체는 맨 앞 8바이트에 **vfptr** 을 둔다. `b->run()` 은 다음으로 번역된다(g++ -O0):

```asm
mov rax, [rbp-0x10]   ; rax = b           (객체 포인터)
mov rax, [rax]        ; rax = vfptr        ← vtable base 로드
mov rdx, [rax]        ; rdx = vtable[0]    ← slot 로드 (run())
mov rdi, [rbp-0x10]   ; rdi = this
call rdx              ; 간접 호출          ← 가상 디스패치
```

공격자는 UAF/힙 오버플로로 **vfptr 을 덮어** 가짜 테이블을 가리키게 한다.
- **injection**: vfptr → 힙의 가짜 vtable(쓰기 가능)
- **reuse**: vfptr → .rodata 의 함수 포인터 배열(읽기 전용, vtable 아님)

**관찰**: 정상 vtable 은 읽기 전용, 주입 vtable 은 쓰기 가능. 가상 호출 직전 성질만 보면 구분 가능.

---

## 2. ① ELFParser — 후보 vtable 식별

원논문 PEParser 는 relocation 테이블에서 "코드 섹션을 가리키는 포인터 배열" 을 후보 vtable 로
식별한다. `-no-pie` ELF 에서는 포인터가 절대주소로 섹션에 박혀 있으므로, 읽기 전용 섹션을
8바이트 단위로 훑어 **Itanium ABI vtable 패턴** 을 찾는다.

```
[ offset-to-top = 0 ][ typeinfo* (코드 아님) ][ fn0* (코드) ][ fn1* (코드) ] ...
                                               ▲ vfptr 이 가리키는 address point (= 시작+16)
```

실측 예:
```
_ZTV7Derived @ 0x402028   addr_point 0x402038   slot0 = 0x401274 (Derived::run)
_ZTV4Base    @ 0x402050   addr_point 0x402060   slot0 = 0x401256 (Base::run)
```

## 3. ② BitCover — 가상 호출 지점 · vtable 참조 식별

capstone 으로 실행 섹션을 디스어셈블하여 두 가지를 찾는다.

**(a) 가상 호출 지점**: 간접 `call rSLOT` 에서 역추적하여
`mov rBASE,[rTHIS]`(base 로드) → `mov rSLOT,[rBASE+disp]`(slot 로드) 연속 쌍을 **계측 윈도우** 로 확정.
base 로드 직후 `rBASE = vtable base` 가 살아 있으므로 여기서 검사할 수 있다.

```
window @0x401605 : 48 8b 00 48 8b 10   (mov rax,[rax] ; mov rdx,[rax])   len=6
call   @0x401612 : call rdx            resume @0x40160b
```

**(b) vtable 참조**: 생성자가 vfptr 에 vtable 주소점을 대입하는 immediate 를 찾는다(패치 대상).
```
0x401394: mov edx, 0x402038   ; Derived vtable+16
0x401306: mov edx, 0x402060   ; Base vtable+16
```

## 4. ③ VRewriter — 실제 바이너리 재작성

1. **vtsec 생성(0x500000, 읽기 전용)**
   - 페이지 선두 8바이트에 **랜덤 ID** 기록
   - 확정된 vtable 들을 **그대로 복사(이전)** → 새 주소점 기록
2. **검사 코드 세그먼트(0x600000, 읽기+실행)**
   - `runtime/vtint_check.c` 를 `-DVTINT_ID=<ID>` 로 freestanding 컴파일 → 링크(0x600000) → objcopy → **머신코드 블롭 주입**
   - 가상 호출마다 **트램펄린** 생성
3. **코드 패치**
   - 생성자 vtable 참조 immediate → 새 vtsec 주소점으로 교체
   - 계측 윈도우 → `jmp rel32`(트램펄린) + nop 패딩

### 트램펄린 동작
```asm
<base load>              ; rBASE = vtable base  (윈도우에서 이전)
push rBASE ; push rBASE  ; 저장 + 16B 정렬
mov  rdi, rBASE          ; 인자
movabs rax, &__vtint_check
call rax                 ; 검사 → 실패 시 내부에서 exit(99)
pop  rBASE ; pop rBASE   ; 복원
<slot load>              ; rSLOT = vtable[k]   (윈도우에서 이전)
jmp  resume              ; 원래 호출 지점으로
```

### 검사 루틴 `__vtint_check(vtbl)` (freestanding, raw syscall)
```
page = vtbl & ~0xFFF
/proc/self/maps 에서 vtbl 이 속한 매핑의 권한 조회
  └ 'w' 이면  → VTINT DETECTED READONLY (exit 99)     ← injection 차단
*(u64*)page != ID → VTINT DETECTED ID       (exit 99)  ← rodata reuse 차단
그 외          → 복귀하여 정상 디스패치
```

---

## 5. 왜 세 사례가 구분되는가

| 시나리오 | vfptr 가리키는 곳 | 매핑 권한 | 페이지 ID | 판정 |
|---|---|---|---|---|
| 정상 | vtsec(이전된 vtable) | `r--p` | 일치 | 통과 → DERIVED RUN |
| injection | 힙 가짜 vtable | `rw-p` | — | **READONLY 실패** |
| rodata reuse | .rodata 배열 | `r--p` | 불일치 | **ID 실패** |

종료 코드: 0=정상, 66=탈취(HIJACKED), 99=탐지·차단.
