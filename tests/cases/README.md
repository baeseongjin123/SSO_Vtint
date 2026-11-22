# 테스트케이스 프로그램 (정상·위반·경계)

팀원의 VTint 구현을 검증하기 위한 **취약 대상 프로그램**들. 각 프로그램은 팀원 `tests/victim.cpp`
와 같은 인터페이스를 따른다.

- 입력: `argv[1]` = `normal` | `inject` | `rodata`
- 출력: `DERIVED RUN`(정상) / `HIJACKED` / `[leak] ...` (stdout) — victim 과 같은 문구라 팀원 `vtint.py judge` 로도 판정됨
- 종료 코드: 0 정상, 66 탈취. 보호 후에는 런타임이 `VTINT DETECTED ... (99)`

세 프로그램이 한 프로그램 안에서 모드로 세 사례를 모두 재현한다. VTint 적용 전·후로 각각 실행해
비교한다 (`tests/test_cases.py` 가 자동으로 수행).

| 프로그램 | 특징 | 왜 분리했나 |
|---|---|---|
| `tc1_*` | 단일 상속, 대상 가상 함수가 **slot 0**, 스택 객체 | 가장 기본 형태 |
| `tc2_*` | **다른 클래스 계층**(Logger/FileLogger), slot 0 | VTint 가 특정 vtable 이 아니라 모든 vtable 을 보호하는지 |
| `tc3_*` | 대상 가상 함수가 **slot 1**(두 번째 가상 함수) | 탐지가 호출 슬롯이 아니라 vtable base 기준인지, 재작성기가 slot offset 을 다루는지 |

빌드 옵션은 팀원 `tests/build.sh` 와 동일해야 한다(`-O0 -no-pie -fno-devirtualize ...`).
`tests/conftest.py` 의 `CXXFLAGS` 가 그 옵션을 그대로 복사해 둔다.

새 케이스 추가 방법은 [`HOW_TO_ADD.md`](HOW_TO_ADD.md), 한 케이스 빌드는 `bash tests/cases/build_case.sh <이름>`.
