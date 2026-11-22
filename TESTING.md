# VTint 상세 테스트 가이드

본 문서는 [프로젝트 README](README.md)의 기본 실행 안내를 보완하는 상세 테스트 가이드이다.

테스트는 pytest 기반으로 구성되며, 바이너리 재작성 결과, 런타임 검사, 공격 탐지, 정상 호출의 오탐 여부를 검증한다.

## 1. 테스트 구성

| 구분 | 테스트 파일 | 검증 내용 |
| --- | --- | --- |
| A | `test_build.py` | ELF 재작성 결과, vtsec 정렬, ID 기록, 호출 계측 |
| B | `test_build.py` | 실행 중 vtsec 및 검사 코드의 메모리 권한 |
| C | `test_runtime_unit.py` | 다양한 메모리 영역에 대한 READONLY·ID 판정 |
| D | `test_fixed_cases.py` | 11주차 고정 정상·위반·경계 사례 |
| E | `test_false_positive.py` | 상속 구조, 반복 호출, 대규모 vtable의 오탐 검사 |
| F | `test_cases.py` | 직접 작성한 tc1·tc2·tc3 프로그램 검증 |

### A. 바이너리 재작성 검증

보호 바이너리가 다음 조건을 만족하는지 검사한다.

- ELF 실행 파일 형식 및 full RELRO 유지
- vtsec 세그먼트의 4KB 정렬과 읽기 전용 권한
- 검사 코드 세그먼트의 읽기·실행 권한
- vtable 복사 및 참조 패치
- ID 저장 공간 확보 및 무작위 ID 기록
- 가상 함수 호출 지점 계측

### B. 실행 중 메모리 검사

GDB를 이용하여 실제 메모리 매핑 권한을 확인한다.

| 대상 | 기대 권한 |
| --- | --- |
| vtsec | `r--p` |
| VTint 검사 코드 | `r-xp` |
| 힙의 가짜 vtable | `rw-p` |
| `.rodata` 함수 포인터 배열 | `r--p` |

GDB 테스트를 위해 Docker 컨테이너에 `SYS_PTRACE` 권한이 필요하다.

### C. 런타임 단위 테스트

`runtime/vtint_check.c`를 별도 테스트 하네스와 연결하여 검사한다.

주요 검증 조건은 다음과 같다.

- 읽기 전용 페이지와 정상 ID → 통과
- 힙·스택·쓰기 가능 데이터 → READONLY 탐지
- 읽기 전용 페이지와 잘못된 ID → ID 탐지
- NULL·매핑 해제 주소 → READONLY 탐지
- 페이지 경계에 위치한 주소 → 기대한 ID 판정
- 대규모 `/proc/self/maps` → 정상 주소에 대한 오탐 여부 확인

### D. 고정 검증 사례

11주차에 정의된 세 가지 검증 사례를 사용한다.

고정 사례의 입력과 기대 결과는 `fixed/fixed_cases.json`에 정의되어 있으며, `fixed/SHA256SUMS`를 이용하여 변경 여부를 검증한다.

판정 시 다음 항목을 확인한다.

- 종료 코드
- 정상 또는 공격 실행 여부
- READONLY·ID 탐지 종류
- 탐지된 vfptr 주소와 공격 입력 주소의 일치 여부
- 메모리 매핑 권한
- 시그널 종료 및 시간 초과 여부

### E. 오탐 테스트

정상적인 가상 함수 호출이 VTint에 의해 차단되지 않는지 확인한다.

| 테스트 | 대상 |
| --- | --- |
| E1 | Base / Derived / Other 클래스 |
| E2 | 다중 상속 및 두 번째 vptr |
| E3 | 가상 함수 1,000회 반복 호출 |
| E4 | victim 정상 호출 |
| E5 | 200개 vtable을 포함하는 프로그램 |

### F. 추가 테스트케이스

`cases/`에 다음 세 프로그램이 구현되어 있다.

| 프로그램 | 특징 |
| --- | --- |
| tc1 | 단일 상속, 스택 객체, slot 0 |
| tc2 | 단일 상속, 힙 객체, slot 0 |
| tc3 | 다단계 상속(A→B→C), slot 0 |

각 프로그램에서 정상·위반·경계 입력을 보호 전후에 적용하고 결과를 비교한다.

---

## 2. 개별 테스트 실행

다음 명령어는 프로젝트 루트 디렉터리에서 실행한다.

Docker 컨테이너 안에서 실행하는 경우에도 동일한 `test.sh` 명령어를 사용할 수 있다.

### 테스트 파일별 실행

```bash
# 고정 검증 사례
bash test.sh tests/test_fixed_cases.py

# 추가 테스트케이스
bash test.sh tests/test_cases.py -v

# 바이너리 재작성 및 메모리 권한
bash test.sh tests/test_build.py

# 런타임 검사
bash test.sh tests/test_runtime_unit.py

# 오탐 검사
bash test.sh tests/test_false_positive.py
```

### 입력 유형별 실행

```bash
# 정상 호출
bash test.sh -k normal

# vtable injection
bash test.sh -k inject

# .rodata 재사용
bash test.sh -k rodata
```

Docker에서 선택적으로 실행하려면 다음 명령어를 사용할 수 있다.

```bash
# test.sh에 실행 권한이 있는 경우
bash docker-test.sh tests/test_fixed_cases.py
```

현재 `docker-test.sh`는 컨테이너 내부에서 `./test.sh`를 호출한다. 따라서 실행 전 다음 명령어가 필요할 수 있다.

```bash
chmod +x test.sh
```

실행 권한을 변경하지 않고 Docker에서 특정 테스트를 실행하려면 다음과 같이 직접 호출할 수도 있다.

```bash
docker run --rm \
  --cap-add=SYS_PTRACE \
  --security-opt seccomp=unconfined \
  -v "$PWD":/work \
  vtint-env \
  bash test.sh tests/test_fixed_cases.py
```

위 명령어는 `vtint-env` 이미지가 이미 빌드된 상태를 전제로 한다.

### 기존 빌드 결과 재사용

테스트 실행 시 바이너리를 다시 빌드하지 않으려면 다음 환경 변수를 사용한다.

```bash
VTINT_NO_BUILD=1 bash test.sh
```

기존 `out/` 디렉터리에 필요한 바이너리가 존재해야 한다.

---

## 3. 수동 검증

자동화 테스트 외에 보호 전후 프로그램을 직접 실행하여 동작을 확인할 수 있다.

Docker 컨테이너에 진입한다.

```bash
bash docker-run.sh bash
```

컨테이너 내부에서 실행한다.

```bash
# 취약 바이너리 빌드
bash tests/build.sh

# VTint 적용
python3 tools/vrewriter.py \
  out/victim_vuln \
  out/victim_hardened
```

이후 동일한 입력을 보호 전후 바이너리에 적용한다.

```bash
./out/victim_vuln inject
echo $?

./out/victim_hardened inject
echo $?

./out/victim_hardened rodata
echo $?

./out/victim_hardened normal
echo $?
```

출력 문자열, 종료 코드, 탐지된 주소 및 메모리 영역을 비교한다.

---

## 4. 테스트 결과 파일

테스트 실행 시 다음 경로에 결과가 생성된다.

```
results/
├── before_after.md
├── env.txt
└── logs/
```

| 파일 | 기록 내용 |
| --- | --- |
| `before_after.md` | 테스트 프로그램별 보호 전후 판정 |
| `env.txt` | OS, 컴파일러, Python 라이브러리 버전 |
| `logs/` | 개별 테스트의 명령어, 출력, 종료 코드 |

`results/`는 테스트할 때마다 변경되므로 Git 관리에서 제외되어 있다.

### 제출용 결과 보존

특정 시점의 검증 결과를 저장하려면 다음 명령어를 사용한다.

```bash
bash tests/save_results.sh week13
```

저장 결과는 `docs/results/week13/`에 생성된다.

```
docs/results/week13/
├── before_after.md
├── pytest_output.txt
├── env.txt
└── saved_at.txt
```

---

## 5. 오류 해결

| 증상 | 원인 및 해결 방법 |
| --- | --- |
| `Cannot connect to the Docker daemon` | Docker Desktop 실행 및 WSL 통합 설정 확인 |
| `./test.sh: Permission denied` | `chmod +x test.sh` 실행 |
| Ubuntu 패키지 서버 DNS 오류 | Docker Desktop 및 컨테이너 네트워크 연결 확인 |
| GDB 테스트가 건너뛰어짐 | `SYS_PTRACE` 및 seccomp 설정 확인 |
| 결과 파일이 생성되지 않음 | 프로젝트 루트에서 실행했는지 확인 |
| `VTINT DETECTED ID`가 정상 호출에서 발생 | vtable 주소점 및 페이지 ID 확인 |
| `region=[unmapped]` 오탐 | 메모리 매핑 정보 읽기 및 주소 탐색 과정 확인 |
