# VTint 테스트 실행 안내

이 폴더는 팀원이 만든 VTint(바이너리 재작성) 구현이 **정상·위반·경계** 세 사례에서
제대로 동작하는지 자동으로 확인한다. 처음 보는 사람도 **명령 한 줄**로 돌릴 수 있다.

구현 설명은 저장소 루트의 `README.md`, 테스트 설계·결과는 `docs/TEST_PLAN.md` 참고.

---

## 1. 준비물

- **Docker Desktop** 하나면 된다. (컴파일러·파이썬 라이브러리·gdb 가 모두 Docker 이미지 안에 들어 있어서, 내 PC 에 따로 설치할 게 없다.)
- Docker Desktop 을 실행해 두고(고래 아이콘이 초록색/Running), 아래 명령을 저장소 **루트**에서 실행한다.

> 리눅스/맥이고 도구가 이미 깔려 있다면 Docker 없이도 돌릴 수 있다 → 아래 **5. Docker 없이**.

---

## 2. 가장 쉬운 실행 (Docker, 권장)

### Windows (PowerShell)
저장소 루트(`SSO_Vtint`)에서:

```powershell
docker build -t vtint-env .
docker run --rm --cap-add=SYS_PTRACE --security-opt seccomp=unconfined -v "${PWD}:/work" vtint-env bash -lc "./test.sh"
```

### macOS / Linux (터미널)
```bash
./docker-test.sh
```

처음 한 번은 이미지를 받느라 몇 분 걸리고, 그다음부터는 빠르다.
`--cap-add=SYS_PTRACE ...` 는 실행 중 메모리 상태를 보는 gdb 테스트에 필요하다(빼면 그 테스트만 건너뛴다).

---

## 3. 결과 보기

성공하면 마지막 줄이 이렇게 나온다:

```
=============== 59 passed, 4 failed in 18s ===============
```

- **정상·위반·경계 핵심 결과**는 `results/before_after.md` 에 표로 자동 저장된다. 보고서에 그대로 붙이면 된다.
- 실행별 상세 로그(명령·출력·종료 코드)는 `results/logs/` 에 쌓인다.
- 환경 정보(OS, 컴파일러·라이브러리 버전)는 `results/env.txt`.

### "4 failed" 는 정상인가?
그렇다. 현재 **실패 4개는 테스트가 틀린 게 아니라 구현에서 찾은 문제**다(2차 vptr, vtsec 4KB 초과, maps 64KB 초과). 원인과 수정안은 `docs/TEST_PLAN.md` 3장에 정리돼 있다. 고치면 숫자가 줄어든다.

핵심 확인용 **고정 사례 3종(D)** 과 **직접 만든 테스트케이스 3종(F)** 은 모두 통과해야 정상이다.

---

## 4. 일부만 돌리기

전체가 아니라 보고 싶은 부분만 돌리려면 뒤에 `-k 키워드` 를 붙인다.

| 목적 | Windows (`... bash -lc "..."` 안에) | mac/Linux |
|---|---|---|
| 고정 사례 3종만 | `./test.sh tests/test_fixed_cases.py` | `./docker-test.sh tests/test_fixed_cases.py` |
| 직접 만든 3종만 | `./test.sh tests/test_cases.py -v` | `./docker-test.sh tests/test_cases.py -v` |
| 정상 사례만 | `./test.sh -k normal` | `./docker-test.sh -k normal` |
| 위반(주입)만 | `./test.sh -k inject` | `./docker-test.sh -k inject` |
| 경계(rodata)만 | `./test.sh -k rodata` | `./docker-test.sh -k rodata` |

예 (Windows, 직접 만든 3종만):
```powershell
docker run --rm --cap-add=SYS_PTRACE --security-opt seccomp=unconfined -v "${PWD}:/work" vtint-env bash -lc "./test.sh tests/test_cases.py -v"
```

---

## 5. Docker 없이 (리눅스/맥, 선택)

필요 도구: `g++`, `gdb`, `python3`, 그리고 파이썬 라이브러리.
```bash
pip3 install pyelftools==0.31 capstone==5.0.1 lief==0.15.1 pytest==8.3.3
./test.sh
```

---

## 6. 무엇을 확인하는가 (테스트 구성)

| 파일 | 확인 내용 |
|---|---|
| `test_fixed_cases.py` | **11주차 고정 사례 3종**(정상·위반·경계), 보호 전·후 비교 |
| `test_cases.py` + `cases/` | **직접 만든 테스트케이스 3종**(tc1 스택 / tc2 힙 / tc3 다단계 상속), 각각 세 사례 |
| `test_build.py` | 재작성 결과물이 전제를 만족하는지(vtsec 읽기 전용, ID, 계측) + 실행 중 메모리 맵 |
| `test_runtime_unit.py` + `unit/` | 검사 루틴 하나에 여러 주소를 넣어 판정 확인 |
| `test_false_positive.py` + `progs/` | 정상 입력에서 오탐이 없는지 |

세 사례가 보호 전·후로 어떻게 달라지는지:

| 사례 | 모드 | 보호 전 | 보호 후 |
|---|---|---|---|
| 정상 | `normal` | `DERIVED RUN`, 종료 0 | 똑같음 (막지 않음) |
| 위반 | `inject` | `HIJACKED`, 종료 66 | `VTINT DETECTED READONLY`, 종료 99 |
| 경계 | `rodata` | `HIJACKED`, 종료 66 | `VTINT DETECTED ID`, 종료 99 |

---

## 7. 직접 하나씩 실행해 보고 싶다면

테스트를 거치지 않고 손으로 확인하는 방법. Docker 셸에 들어가서:

```powershell
docker run --rm -it -v "${PWD}:/work" vtint-env bash
```
(mac/Linux: `./docker-run.sh bash`)

셸 안에서:
```bash
bash tests/build.sh                                   # 취약 바이너리 → out/victim_vuln
python3 tools/vrewriter.py out/victim_vuln out/victim_hardened   # VTint 적용 → out/victim_hardened

./out/victim_vuln    inject   ; echo "종료 코드 $?"   # 보호 전: HIJACKED / 66
./out/victim_hardened inject  ; echo "종료 코드 $?"   # 보호 후: VTINT DETECTED READONLY / 99
./out/victim_hardened rodata  ; echo "종료 코드 $?"   # 보호 후: VTINT DETECTED ID / 99
./out/victim_hardened normal  ; echo "종료 코드 $?"   # 정상: DERIVED RUN / 0
```
`mode` 자리에 `normal` / `inject` / `rodata` 를 바꿔 넣으면 세 사례를 각각 볼 수 있다.

---

## 8. 잘 안 될 때

| 증상 | 해결 |
|---|---|
| `Cannot connect to the Docker daemon` | Docker Desktop 이 안 켜졌거나 아직 준비 중. 고래 아이콘이 Running 될 때까지 기다린 뒤 다시 실행 |
| `-v "${PWD}:/work"` 가 Windows 에서 안 먹음 | **PowerShell** 에서 실행 중인지 확인(`${PWD}` 는 PowerShell 문법). cmd 면 `%cd%` 로 바꾼다 |
| gdb(B) 테스트가 `skip` 됨 | `--cap-add=SYS_PTRACE --security-opt seccomp=unconfined` 를 빠뜨렸는지 확인 |
| 결과가 `results/` 에 안 생김 | 저장소 **루트**에서 실행했는지, `-v` 마운트 경로가 맞는지 확인 |
| 한글이 깨져 보임 | 터미널 인코딩 문제일 뿐, 판정(종료 코드)에는 영향 없음 |

---

## 9. 새 테스트케이스 추가하기

`tests/cases/` 에 `tcN.h`, `tcN_factory.cpp`, `tcN_main.cpp` 세 파일을 넣으면 자동 테스트가 알아서 찾는다.
손으로 확인할 때는 `bash tests/cases/build_case.sh tcN` 으로 빌드·VTint 적용을 한 번에 한다.
자세한 순서와 규칙: [`cases/HOW_TO_ADD.md`](cases/HOW_TO_ADD.md)

---

## 10. 제출·보고서용 결과 저장하기

`results/` 는 테스트를 돌릴 때마다 바뀌어서(힙 주소, PC 환경) git 에서 제외돼 있다.
보고서를 쓰거나 제출할 때는 그 시점 결과를 따로 저장해서 **이것만 커밋**한다.

```bash
bash tests/save_results.sh week13      # Docker 셸 안에서 (이름은 자유)
```
테스트를 한 번 돌리고 `docs/results/week13/` 에 아래 파일을 남긴다.

| 파일 | 내용 |
|---|---|
| `before_after.md` | 정상·위반·경계 보호 전·후 비교표 (보고서에 그대로 사용) |
| `pytest_output.txt` | 테스트 화면 출력, 통과/실패 요약 |
| `env.txt` | 실행 환경(OS, 컴파일러, 라이브러리 버전) |
| `saved_at.txt` | 저장한 시각 |

Windows PowerShell 에서 바로:
```powershell
docker run --rm --cap-add=SYS_PTRACE --security-opt seccomp=unconfined -v "${PWD}:/work" vtint-env bash tests/save_results.sh week13
```
