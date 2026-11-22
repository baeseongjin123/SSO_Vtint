# VTint — 가상 함수 테이블 무결성 보호

> 소프트웨어및시스템보안 · 논문 구현 프로젝트 · **3팀**
> 
> 
> 선정 논문: *VTint: Protecting Virtual Function Tables' Integrity* (NDSS 2015)
> 

## 프로젝트 소개

본 프로젝트는 C++ 프로그램의 **가상 함수 테이블(vtable) 탈취 공격을 탐지하고 차단하는 VTint**를 구현한 프로젝트이다.

원논문은 Windows PE 바이너리를 대상으로 하지만, 본 구현에서는 VTint의 핵심 방어 기법을 **Linux x86-64 ELF 환경**에 적용하였다.

컴파일된 ELF 바이너리를 입력받아 `ELFParser → BitCover → VRewriter`의 3단계를 거쳐 보호 바이너리를 생성하며, 가상 함수 호출 직전에 READONLY 및 ID 검사를 수행하여 공격 여부를 판정한다.

## 1. 실행 환경

| 항목 | 버전 |
| --- | --- |
| 운영체제 | Ubuntu 22.04 (x86-64) |
| 개발 환경 | Linux / WSL2 / Docker |
| Python | 3.10.12 |
| GCC/G++ | 11.4.0 |
| pyelftools | 0.31 |
| Capstone | 5.0.1 |
| LIEF | 0.15.1 |
| pytest | 8.3.3 |

Docker 사용을 권장하며, Dockerfile을 통해 필요한 의존성을 자동으로 설치할 수 있다.

## 2. 설치 및 실행

### 2.1 저장소 복제

```bash
git clone https://github.com/baeseongjin123/SSO_Vtint.git
cd SSO_Vtint
git switch tests
```

### 2.2 Docker 실행

프로젝트 루트 디렉터리에서 다음 명령어를 실행한다.

```bash
bash docker-run.sh
```

실행 시 다음 과정이 자동으로 진행된다.

1. Docker 이미지(`vtint-env`) 빌드
2. 취약 바이너리 컴파일
3. ELF 바이너리 분석 및 가상 호출 지점 탐색
4. VTint 검사 코드 삽입 및 보호 바이너리 생성
5. 보호 적용 전·후 실행 결과 비교

Docker 컨테이너 내부에 직접 접근하려면 다음 명령어를 사용한다.

```bash
bash docker-run.sh bash
```

### 2.3 로컬 Linux 실행

Docker를 사용하지 않는 경우 필요한 패키지를 설치한다.

```bash
sudo apt-get update
sudo apt-get install -y \
    gcc g++ binutils python3 python3-pip gdb
```

Python 라이브러리를 설치한다.

```bash
python3 -m pip install \
    pyelftools==0.31 \
    capstone==5.0.1 \
    lief==0.15.1 \
    pytest==8.3.3
```

설치 후 다음 명령어를 실행한다.

```bash
bash run.sh
```

## 3. 구현 구조

VTint는 가상 함수 호출 직전에 vtable의 무결성을 검사하여 공격을 탐지한다.

### 3.1 방어 원리

C++ 다형성 객체는 가상 함수 호출을 위해 vtable 포인터(vfptr)를 사용한다. 공격자가 메모리 취약점을 이용해 vfptr을 위조하면 실행 흐름을 탈취할 수 있다.

이를 방지하기 위해 두 가지 검사를 수행한다.

- **READONLY 검사:** vtable이 쓰기 가능한 메모리 영역에 존재하는지 확인하여 힙에 생성된 가짜 vtable을 탐지한다.
- **ID 검사:** 읽기 전용 영역에 존재하더라도 보호용 식별자(ID)가 일치하지 않으면 위조된 vtable로 판단하여 차단한다.

검사에 실패하면 탐지 메시지를 출력하고 종료 코드 `99`로 프로그램을 중단한다.

### 3.2 바이너리 재작성 과정

```
원본 ELF 바이너리
        |
        v
    ELFParser
  (vtable 후보 탐색)
        |
        v
     BitCover
  (가상 호출 지점 분석)
        |
        v
    VRewriter
  (검사 코드 삽입)
        |
        v
   보호 ELF 바이너리
        |
        v
  READONLY / ID 검사
```

| 모듈 | 파일 | 역할 |
| --- | --- | --- |
| ELFParser | `tools/elfparser.py` | ELF 구조 분석 및 vtable 후보 식별 |
| BitCover | `tools/bitcover.py` | 가상 호출 지점과 vtable 참조 분석 |
| VRewriter | `tools/vrewriter.py` | vtable 이전 및 보호 코드 삽입 |
| Runtime | `runtime/vtint_check.c` | READONLY 및 ID 검사 수행 |
| CLI | `tools/vtint.py` | 분석·재작성·실행 과정 통합 |

자세한 구현 구조는 [아키텍처 문서](docs/architecture.md)를 참고한다.

## 4. 사용 방법

전체 과정을 자동으로 실행하려면 다음 명령어를 사용한다.

```bash
bash run.sh
```

각 기능을 개별적으로 실행할 수도 있다.

```bash
# 취약 바이너리 컴파일
bash tests/build.sh

# ELF 파싱 및 vtable 탐색
python3 tools/elfparser.py out/victim_vuln

# 가상 함수 호출 지점 분석
python3 tools/bitcover.py out/victim_vuln

# 보호 바이너리 생성
python3 tools/vrewriter.py \
    out/victim_vuln out/victim_hardened

# 보호 바이너리 실행 및 판정
python3 tools/vtint.py judge \
    out/victim_hardened inject
```

빌드 및 재작성된 실행 파일은 `out/` 디렉터리에 생성된다.

## 5. 테스트 및 검증

### 5.1 테스트 실행

본 프로젝트는 pytest 기반 자동화 테스트를 제공한다.

**Docker 환경**

```bash
bash docker-test.sh
```

**로컬 Linux 환경**

```bash
bash test.sh
```

**고정 검증 사례만 실행**

```bash
bash test.sh -k D
```

테스트 구성과 세부 실행 방법은 [테스트 안내 문서](TESTING.md)를 참고한다.

### 5.2 보호 적용 전·후 비교

11주차에 정의한 정상·위반·경계 사례를 이용하여 동일한 입력에 대한 보호 적용 전·후 결과를 비교하였다.

| 구분 | 입력 | 보호 전 | 보호 후 |
| --- | --- | --- | --- |
| 정상 | `normal` | 정상 실행 (exit 0) | 정상 실행 (exit 0) |
| 위반 | `inject` | 제어 흐름 탈취 (exit 66) | READONLY 탐지 (exit 99) |
| 경계 | `rodata` | 제어 흐름 탈취 (exit 66) | ID 탐지 (exit 99) |

`victim`, `tc1`, `tc2`, `tc3`의 네 가지 프로그램에 대해 정상·위반·경계 사례를 각각 실행하였으며, **총 12개 비교 사례가 모두 기대 결과와 일치**하였다.

종료 코드의 의미는 다음과 같다.

- `0`: 정상 실행
- `66`: 제어 흐름 탈취 발생
- `99`: VTint 탐지 및 차단

### 5.3 전체 테스트 결과

테스트 결과는 다음과 같다.

```
4 failed, 60 passed, 2 warnings in 12.71s
```

| 항목 | 결과 |
| --- | --- |
| 전체 테스트 | 64개 |
| 통과 | 60개 |
| 실패 | 4개 |
| 경고 | 2건 |
| 실행 시간 | 12.71초 |

핵심 방어 시나리오는 모두 통과하였으나, 확장 테스트에서는 정상 호출이 공격으로 잘못 탐지되는 오탐(False Positive)이 확인되었다.

실패 사례는 다음과 같다.

| 테스트 | 문제 |
| --- | --- |
| E2_multi_base2 | 다중 상속의 두 번째 vptr에서 ID 오탐 |
| E5_first | 4KB 초과 vtable 영역에서 ID 오탐 |
| E5_all | 다수 vtable 사용 시 ID 오탐 |
| C14_big_maps | 큰 `/proc/self/maps` 입력에서 READONLY 오탐 |

해당 문제는 추가 분석 및 개선이 필요한 상태이다.

## 6. 프로젝트 구조

```
SSO_Vtint/
├── README.md
├── Dockerfile
├── docker-run.sh
├── docker-test.sh
├── run.sh
├── test.sh
├── pytest.ini
│
├── tools/
│   ├── elfparser.py
│   ├── bitcover.py
│   ├── vrewriter.py
│   └── vtint.py
│
├── runtime/
│   ├── vtint_check.c
│   └── check.ld
│
├── tests/
│   ├── build.sh
│   ├── victim.cpp
│   ├── factory.cpp
│   ├── test_build.py
│   ├── test_cases.py
│   ├── test_fixed_cases.py
│   ├── test_runtime_unit.py
│   ├── test_false_positive.py
│   ├── cases/
│   ├── fixed/
│   ├── progs/
│   └── unit/
│
├── docs/
│   ├── architecture.md
│   ├── animation.html
│   ├── TEST_PLAN.md
│   ├── PROJECT_OVERVIEW.md
│   └── results/
│       └── week12/
│           ├── before_after.md
│           ├── pytest_output.txt
│           ├── env.txt
│           └── saved_at.txt
│
└── out/                  # 실행 후 생성
```

## 7. 구현 범위 및 한계

원논문과 달리 본 프로젝트는 Linux ELF 환경에 맞추어 일부 기능을 변경하였다.

| 항목 | 원논문 | 본 구현 |
| --- | --- | --- |
| 대상 바이너리 | Windows PE | Linux ELF (x86-64) |
| READONLY 검사 | SEH 기반 | `/proc/self/maps` 기반 |
| vtable 식별 | Relocation 정보 활용 | 코드 포인터 배열 및 심볼 분석 |
| 바이너리 재작성 | PE | ELF |
| 모듈 판별 | PEB 기반 | 미구현 |

현재 구현은 `-no-pie`, `-O0`, `-fno-devirtualize` 등의 컴파일 옵션을 사용하는 테스트 바이너리를 중심으로 검증하였다.

다음과 같은 한계가 있다.

- PIE 및 멀티 모듈 환경 미지원
- 일부 컴파일러 최적화 및 가상 호출 패턴에 대한 제약
- 다중 상속 및 대규모 vtable에서 오탐 발생 가능
- 큰 메모리 매핑 정보 처리의 제약
- 기존 정상 vtable을 재사용하는 공격을 완전히 차단하지 못함

따라서 본 구현은 VTint의 핵심 방어 메커니즘을 실험적으로 재현하기 위한 것으로, 모든 ELF 바이너리에 대한 범용적인 보호 기능을 제공하지는 않는다.
