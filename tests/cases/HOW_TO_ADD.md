# 새 테스트케이스 추가하기 (다음 주 참고용)

> 한 줄 요약: **tc1 세 파일을 복사해서 이름만 바꾸고, 바꾸고 싶은 부분만 고친다.**
> 그러면 빌드 스크립트와 자동 테스트가 알아서 새 케이스를 찾아 준다.

---

## 1. 테스트케이스가 뭐였더라?

**취약한 C++ 프로그램 하나**예요. 이 프로그램은 실행할 때 모드를 받아서 세 가지 상황을 재현해요.

| 모드 | 상황 | 보호 전 | 보호 후 (VTint 적용) |
|---|---|---|---|
| `normal` | 정상 | `DERIVED RUN`, 종료 0 | 똑같음 |
| `inject` | 위반 (힙의 가짜 vtable) | `HIJACKED`, 종료 66 | `VTINT DETECTED READONLY`, 종료 99 |
| `rodata` | 경계 (.rodata 배열) | `HIJACKED`, 종료 66 | `VTINT DETECTED ID`, 종료 99 |

이 프로그램을 VTint에 넣으면 보호된 실행 파일이 나오고, 둘을 비교하는 게 테스트예요.

---

## 2. 파일 세 개 = 테스트케이스 하나

`tests/cases/` 안에 **이름이 같은 세 파일**을 둬요. 이름은 자유인데 `tc4`, `tc5` 처럼 쓰면 편해요.

| 파일 | 들어가는 것 |
|---|---|
| `tc4.h` | 클래스 선언 (가상 함수 있는 부모·자식) |
| `tc4_factory.cpp` | 클래스 함수 내용, 객체 만드는 함수, 공격자 함수 `hijacked()` |
| `tc4_main.cpp` | `main`: 모드에 따라 정상 / 위반 / 경계 실행 |

> 파일을 왜 나누나요? 객체를 만드는 코드를 `main`과 다른 파일에 두어야 컴파일러가 가상 호출을 없애 버리지 않아요. 가상 호출이 없어지면 VTint가 검사할 대상도 없어져요.

---

## 3. 만드는 순서 (4단계)

### ① tc1을 복사해서 이름 바꾸기
```bash
cd tests/cases
cp tc1.h tc4.h
cp tc1_factory.cpp tc4_factory.cpp
cp tc1_main.cpp tc4_main.cpp
```
그리고 세 파일 안의 `#include "tc1.h"` 를 `#include "tc4.h"` 로 바꿔요.

### ② 시험하고 싶은 부분만 고치기
예를 들면 이런 것들이에요.
- 클래스 이름이나 상속 구조 (tc3처럼 여러 단계 상속)
- 객체를 두는 위치 (tc1은 스택, tc2는 힙)
- 맨 위 주석에 "이 케이스는 무엇을 시험하는지" 한두 줄 적기

### ③ 손으로 확인하기 (Docker 셸 안에서)
```bash
bash tests/cases/build_case.sh tc4
python3 tools/vtint.py judge out/tc4_vuln     inject   # 보호 전 → 제어흐름 탈취(rc=66) 이어야 함
python3 tools/vtint.py judge out/tc4_hardened inject   # 보호 후 → 탐지·차단(READONLY)(rc=99)
python3 tools/vtint.py judge out/tc4_hardened rodata   # 보호 후 → 탐지·차단(ID)(rc=99)
python3 tools/vtint.py judge out/tc4_hardened normal   # 보호 후 → 정상 종료(rc=0)
```
Docker 셸 들어가는 법: 저장소 루트에서 `docker run --rm -it -v "${PWD}:/work" vtint-env bash`

### ④ 자동 테스트로 채점하기
```bash
./test.sh -k tc4
```
`test_cases.py` 를 고칠 필요 없어요. `tc4_main.cpp` 가 있으면 자동으로 찾아서 세 사례를 보호 전·후로 6번 채점해요.

---

## 4. 꼭 지켜야 할 규칙 (팀원 구현과 맞추기)

이걸 안 지키면 VTint가 동작하지 않거나, 판정이 "기타"로 나와요.

| 규칙 | 이유 |
|---|---|
| 모드 이름은 `normal` / `inject` / `rodata` | 팀원 `judge` 와 자동 테스트가 이 이름으로 실행해요 |
| 정상일 때 출력은 정확히 `DERIVED RUN` | 팀원 `judge` 가 이 글자를 보고 "정상 종료"로 판정해요 |
| 공격자 함수는 `HIJACKED` 출력 후 종료 코드 66 | 보호 전 탈취를 알아보는 기준 |
| 유출 주소 출력은 `[leak] fake vtable @ 0x...` / `[leak] rodata fptr array @ 0x...` 그대로 | 테스트가 탐지된 주소와 이 주소를 비교해요 |
| 호출하는 가상 함수는 클래스에서 **맨 먼저 선언** (slot 0) | 지금 팀원 구현은 slot 0 호출만 보호해요 (아래 5번) |
| 컴파일은 `build_case.sh` 로 | 옵션이 팀원 `build.sh` 와 똑같이 맞춰져 있어요 |
| `main.cpp` 에서 가상 호출 직전에 `fflush(stdout)` | 안 하면 `[leak]` 줄이 사라질 수 있어요 |

---

## 5. 결과가 기대와 다르면?

**기대값을 바꾸지 말고, 왜 다른지 기록**하는 게 과제 규칙이에요. 13주차가 바로 이런 "반례 찾기" 주예요.

| 결과 | 뜻 | 할 일 |
|---|---|---|
| 보호 전에 `HIJACKED` 가 안 나옴 | 공격이 성립 안 함 → 테스트케이스 문제 | 내 코드 확인 (fflush, 파일 분리, 컴파일 옵션) |
| 보호 후에도 `HIJACKED` | VTint가 이 호출을 못 막음 | 반례로 기록 |
| 정상인데 `VTINT DETECTED` | 오탐 | 반례로 기록 |
| `judge` 가 정상을 "기타"로 판정 | 출력 문구가 `DERIVED RUN` 이 아님 | 출력 문구 고치기 |

반례는 둘 중 하나로 분류해서 `docs/TEST_PLAN.md` 에 적어요.
- **구현 버그**: 원논문대로라면 막아야 하는데 못 막음 → 팀원에게 전달
- **한계**: 원논문도 못 막거나, 이번 구현 범위 밖

### 이미 알고 있는 반례 (다음 주 재료)
- **slot 1 호출**: 두 번째 가상 함수를 부르면 보호가 안 돼요. 컴파일된 코드에 `add` 명령이 하나 끼어서 팀원 BitCover가 가상 호출을 못 찾기 때문이에요. → 한계 (자세한 건 `docs/TEST_PLAN.md`)
- 다중 상속 두 번째 vptr, vtable이 많아서 vtsec이 4KB를 넘을 때 → 구현 버그 (`docs/TEST_PLAN.md` 3장)

일부러 반례를 만들 때는 위 4번 규칙 중 **하나만** 어기고, 맨 위 주석에 "무엇을 일부러 바꿨는지"를 적어 두세요. 그래야 결과를 설명하기 쉬워요.

---

## 6. 지금 있는 테스트케이스

| 이름 | 무엇을 시험하나 |
|---|---|
| tc1 | 기본: 단일 상속, 스택 객체 |
| tc2 | 객체가 힙에 있을 때 |
| tc3 | 다단계 상속 (A → B → C) |

새 케이스를 만들면 이 표에 한 줄 추가해 두세요.
