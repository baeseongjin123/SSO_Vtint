# 12주차 보고서 초안 — 테스트케이스 파트

> 이 파일은 12주차 보고서를 쓰는 팀원이 **AI에게 그대로 넣어서** 보고서 문장을 만들 수 있도록 정리한 자료입니다.
> 테스트 담당 파트만 담았습니다. 구현 파트(ELFParser·BitCover·VRewriter)는 구현 담당 자료와 합쳐 주세요.

---

## 0. AI에게 주는 지시 (이 블록을 프롬프트 맨 앞에 붙이세요)

```
너는 "소프트웨어및시스템보안" 12주차 논문 구현 보고서 중 '테스트' 부분을 쓰는 도우미야.
아래 자료에 있는 사실과 숫자만 사용해. 자료에 없는 결과·수치·환경은 지어내지 말고 [확인 필요]로 남겨.
11주차에 정한 기대 결과는 절대 바꾸지 마. 기대와 다른 결과는 '원인 분석'으로만 써.
보고서 양식 순서(1 구현 진행 현황 ~ 6 막힌 점과 요청 사항)에 맞춰, 테스트 관련 내용만 문장으로 정리해.
표는 표로 유지하고, 문체는 "~했다 / ~이다" 보고서체로 써.
```

---

## 1. 구현 진행 현황 (테스트 파트)

**완료**
- pytest 기반 자동 테스트 64개 작성. Docker(Ubuntu 22.04)에서 한 줄로 실행됨.
- 11주차 고정 검증 사례 3종(정상·위반·경계)을 보호 적용 전·후로 자동 판정 → 모두 기대 결과와 일치.
- 팀원 구현 인터페이스에 맞춘 **테스트케이스 프로그램 3종(tc1·tc2·tc3)** 을 직접 작성. 한 프로그램이 모드(`normal`/`inject`/`rodata`)로 세 사례를 모두 재현하며, 3종 모두 세 사례가 기대 결과와 일치.
- 재작성 결과물 검사(vtsec 읽기 전용·ID·계측), 실행 중 메모리 맵 검사(gdb), 검사 루틴 단위 검사, 오탐 검사 작성.
- 실행 결과를 표로 자동 저장(`results/before_after.md`), 제출용 스냅샷 저장 스크립트 작성(`docs/results/week12/`).
- 새 테스트케이스를 쉽게 추가하는 구조 마련(파일 세 개만 넣으면 자동 인식, `tests/cases/HOW_TO_ADD.md`).

**진행 중 / 다음 주로 넘긴 것**
- 다른 팀원 PC에서 재실행 확인 → [확인 필요: 4절]
- 테스트에서 발견한 구현 문제 4건 + 한계 1건을 구현 담당에게 전달하고 수정 후 재확인 (6절)
- 13주차: 검증 사례 확장과 반례 발굴

---

## 2. 실행 방법 (테스트 파트)

**실행 환경** (`docs/results/week12/env.txt` 기준)

| 항목 | 값 |
|---|---|
| 호스트 | Windows 11 + Docker Desktop |
| 컨테이너 OS | Ubuntu 22.04 (glibc 2.35) |
| 컴파일러 | g++ 11.4.0 |
| Python | 3.10.12 |
| 패키지 | pyelftools 0.31, capstone 5.0.1, lief 0.15.1, pytest 8.3.3, gdb 12.1 |

**실행 명령** (저장소 루트에서)

mac/Linux:
```bash
./docker-test.sh
```
Windows PowerShell:
```powershell
docker build -t vtint-env .
docker run --rm --cap-add=SYS_PTRACE --security-opt seccomp=unconfined -v "${PWD}:/work" vtint-env bash -lc "./test.sh"
```
- `--cap-add=SYS_PTRACE ...` 는 실행 중 메모리 맵을 보는 gdb 테스트에 필요.
- 결과: `results/before_after.md`(비교표), `results/logs/`(실행별 로그), `results/env.txt`(환경).
- 상세 안내: `tests/README.md`

---

## 3. 실행 결과 비교

### 3-1. 11주차 고정 사례 3종 (팀원 예제 victim)

| 구분 | 입력 | 기대 결과 (11주차) | 보호 적용 전 | 보호 적용 후 |
|---|---|---|---|---|
| 정상 | `normal` — 오버플로 없는 입력, Base 포인터로 Derived 가상 함수 호출 | 보호 전후 모두 `DERIVED RUN`, 종료 0, `VTINT DETECTED` 없음 | `DERIVED RUN`, 종료 0 | `DERIVED RUN`, 종료 0 |
| 위반 | `inject` — vfptr 을 힙의 가짜 vtable 주소로 덮음 | 보호 전 `HIJACKED`/66, 보호 후 `VTINT DETECTED READONLY` + vfptr/99, `HIJACKED` 없음 | `HIJACKED`, 종료 66 | `VTINT DETECTED READONLY vfptr=0x...0ed4feb0 region=[rw-p]`, 종료 99 |
| 경계 | `rodata` — vfptr 을 .rodata 의 const 함수 포인터 배열 주소로 덮음 | 보호 전 `HIJACKED`/66, 보호 후 READONLY 통과 · `VTINT DETECTED ID` + vfptr/99 | `HIJACKED`, 종료 66 | `VTINT DETECTED ID vfptr=0x...004020b8 region=[r--p]`, 종료 99 |

→ 세 사례 모두 기대 결과와 일치. (힙 주소는 ASLR 때문에 실행마다 달라짐)

### 3-2. 직접 작성한 테스트케이스 3종 (같은 기준으로 판정)

| 프로그램 | 무엇을 시험하나 | 정상 (전→후) | 위반 (전→후) | 경계 (전→후) |
|---|---|---|---|---|
| tc1 | 단일 상속, 스택 객체 | 0 → 0 | 66 → 99 (READONLY) | 66 → 99 (ID) |
| tc2 | 단일 상속, **힙** 객체 | 0 → 0 | 66 → 99 (READONLY) | 66 → 99 (ID) |
| tc3 | **다단계 상속** A→B→C | 0 → 0 | 66 → 99 (READONLY) | 66 → 99 (ID) |

숫자는 종료 코드(0 정상, 66 탈취, 99 탐지). 9가지 모두 기대와 일치. 팀원 `tools/vtint.py judge` 로 판정해도 같은 결과.

### 3-3. 판정 기준 보완 내용과 이유

12주차 피드백("고정 사례는 유지하되 모호한 판정 기준만 구체화")에 따라 **기대 결과는 그대로 두고** 판정 기준만 구체화했다.

| 보완한 기준 | 이유 |
|---|---|
| 종료 코드와 출력 문자열을 **함께** 본다 | 99가 다른 이유로 나온 경우를 걸러내기 위해 |
| 탐지 줄 형식을 고정: `VTINT DETECTED <READONLY\|ID> vfptr=0x... region=[권한]` | 어떤 검사가 막았는지 기계적으로 확인하기 위해 |
| 탐지된 vfptr 이 프로그램이 유출한 주소(`[leak]` 줄)와 **같아야** 통과 | "덮어쓴 바로 그 주소를 잡았다"는 근거 |
| 위반은 region 이 쓰기 가능(`rw-p`), 경계는 `r--p` 이고 탐지가 **ID 한 줄뿐**이어야 통과 | 경계 사례의 핵심(읽기 전용 검사는 통과, ID 검사에서 차단)을 확인하기 위해 |
| 같은 입력을 **5회 반복**해 판정이 같아야 통과 | ASLR로 주소가 바뀌어도 판정이 안정적인지 |
| 시그널 종료·시간 초과는 실패 | 크래시를 "차단"으로 착각하지 않기 위해 |
| 고정 사례 파일을 SHA-256 으로 잠금 | 결과에 맞춰 기대값을 바꾸는 일 방지 (11주차 고정 규칙) |

### 3-4. 전체 자동 테스트 결과

**64개 중 60개 통과, 4개 실패** (`docs/results/week12/pytest_output.txt`, 2026-11-22 저장)
- 고정 사례 3종, 직접 만든 3종, 재작성 결과물 검사, 메모리 맵 검사는 모두 통과.
- 실패 4개는 테스트 오류가 아니라 **구현에서 찾은 문제** → 6절.

---

## 4. 다른 환경에서의 재실행

[확인 필요] 아직 작성자 PC(Windows 11 + Docker Desktop)에서만 실행했다.
다른 팀원 PC에서 아래를 실행하고 결과를 채워 주세요.
```bash
./docker-test.sh                    # mac/Linux
bash tests/save_results.sh week12_<이름>   # 결과 저장(Docker 셸 안)
```
채울 항목: 실행한 사람, OS, 통과/실패 수, `before_after.md` 가 작성자 결과와 같은지(주소 값 제외).

---

## 5. AI 활용 기록 (테스트 파트)

| 항목 | 내용 |
|---|---|
| 사용 AI | Claude (Anthropic) |
| 요청 내용 | 테스트 계획 수립, pytest 테스트 코드와 테스트케이스 프로그램 작성, Docker 실행 환경 구성, 실패 원인 분석 |
| 결과 확인 | 모든 테스트를 Docker에서 **직접 실행**해 결과로 확인. 실패 원인은 `objdump` 디스어셈블과 gdb 메모리 맵으로 확인. 기대 결과는 11주차 보고서 표와 글자 단위로 대조 |
| 채택 | 테스트 층 구성(결과물·메모리 맵·단위·고정 사례·오탐), 판정 기준 구체화 항목 |
| 수정 | ① 처음 테스트는 "입력 파일" 방식을 가정했으나, 팀원 구현이 `argv` 모드 방식이라 인터페이스를 전부 다시 맞춤 ② 테스트케이스 정상 출력을 victim 과 같은 `DERIVED RUN` 으로 통일해 팀원 `judge` 로도 판정되게 함 ③ tc3 을 처음엔 "두 번째 가상 함수 호출"로 만들었으나 구현이 보호하지 못해(6절) 다단계 상속으로 바꾸고, 원래 케이스는 13주차 반례로 분리 |
| 어려웠던 점 | ① 11주차 계획(컴파일 단계 재현)과 실제 구현(바이너리 재작성)이 달라 테스트 대상·출력 형식을 다시 파악해야 했음 → 팀원 저장소 코드를 직접 읽어 인터페이스 정리 ② Docker Desktop 엔진이 늦게 켜져 대기 ③ `.gitignore` 의 `results/` 가 `docs/results/` 까지 숨겨 `/results/` 로 수정 |

---

## 6. 막힌 점과 요청 사항 (테스트에서 발견한 것)

기대값은 바꾸지 않고 원인을 기록했다. 자세한 분석: `docs/TEST_PLAN.md` 3장.

| # | 발견 | 증상 | 원인 (분석) | 분류 |
|---|---|---|---|---|
| 1 | 다중 상속 2차 vptr | 정상 호출인데 `VTINT DETECTED ID` (오탐) | 생성자 패치가 1차 주소점만 바꾸고 2차 vptr 은 원래 .rodata vtable 을 계속 가리킴 | 구현 버그 |
| 2 | vtsec 4KB 초과 (2건) | vtable 이 많으면 둘째 페이지부터 정상 vtable 도 `ID` 탐지 (오탐) | ID 를 vtsec 첫 페이지에만 기록. 원논문은 페이지마다 ID | 구현 버그 |
| 3 | maps 64KB 초과 | 매핑이 매우 많으면 정상 vtable 을 "매핑 없음"으로 판정 (오탐) | 검사 루틴이 `/proc/self/maps` 를 64KB 까지만 읽음 | 구현 한계 |
| 4 | 두 번째 가상 함수 호출 | 보호 후에도 공격이 막히지 않음 | 컴파일된 코드에 `add` 명령이 끼어 BitCover 가 가상 호출을 인식 못 함 → 계측 안 됨 | 구현 한계 (13주차 반례) |

**요청 사항**
- 구현 담당: 위 1~4 수정 검토 (수정안은 `docs/TEST_PLAN.md` 에 정리)
- 조교: 4번처럼 원논문과 다른 범위 제한을 "명세상 미지원(한계)"으로 분류해도 되는지 확인 요청

---

## 7. README "검증 사례" 칸에 넣을 내용

배포된 README 양식의 `## 검증 사례` 표:

| 구분 | 입력 | 기대 결과 |
| --- | --- | --- |
| 정상 | `normal` (오버플로 없음, Base 포인터로 Derived 가상 함수 호출) | 보호 전후 모두 `DERIVED RUN`, 종료 코드 0, `VTINT DETECTED` 없음 |
| 위반 | `inject` (vfptr 을 힙의 가짜 vtable 주소로 덮음) | 보호 전 `HIJACKED`/66 → 보호 후 `VTINT DETECTED READONLY` + vfptr, 종료 코드 99 |
| 경계 | `rodata` (vfptr 을 .rodata 함수 포인터 배열 주소로 덮음) | 보호 전 `HIJACKED`/66 → 보호 후 `VTINT DETECTED ID` + vfptr, 종료 코드 99 |

그 아래 한 줄 추가 권장: "자동 검증: `./docker-test.sh` (자세한 방법은 `tests/README.md`)"

---

## 참고: 근거 파일 위치

| 내용 | 파일 |
|---|---|
| 12주차 실행 결과 원본 | `docs/results/week12/` (`before_after.md`, `pytest_output.txt`, `env.txt`) |
| 테스트 설계·발견 문제 상세 | `docs/TEST_PLAN.md` |
| 11주차 계획과 실제 구현 차이 | `docs/PROJECT_OVERVIEW.md` 3.5절 |
| 테스트 실행 안내 | `tests/README.md` |
| 고정 사례 원문 | `tests/fixed/fixed_cases.json` |
