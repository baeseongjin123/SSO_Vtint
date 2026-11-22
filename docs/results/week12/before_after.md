# 보호 적용 전·후 결과 비교

`./test.sh` 실행 시 자동 생성. victim = 팀원 예제(11주차 고정 사례), tc1~ = 직접 만든 테스트케이스. 로그 원본: `results/logs/`

| 구분 | 입력 | 보호 전 (판정 / 종료 코드) | 보호 후 (판정 / 종료 코드) | 기대 일치 |
|---|---|---|---|---|
| tc1 정상 | `normal` | 정상 종료 / exit=0 | 정상 종료 / exit=0 | O |
| tc1 위반 | `inject` | 제어 흐름 탈취 / exit=66 | 탐지 후 차단 (READONLY) / exit=99 | O |
| tc1 경계 | `rodata` | 제어 흐름 탈취 / exit=66 | 탐지 후 차단 (ID) / exit=99 | O |
| tc2 정상 | `normal` | 정상 종료 / exit=0 | 정상 종료 / exit=0 | O |
| tc2 위반 | `inject` | 제어 흐름 탈취 / exit=66 | 탐지 후 차단 (READONLY) / exit=99 | O |
| tc2 경계 | `rodata` | 제어 흐름 탈취 / exit=66 | 탐지 후 차단 (ID) / exit=99 | O |
| tc3 정상 | `normal` | 정상 종료 / exit=0 | 정상 종료 / exit=0 | O |
| tc3 위반 | `inject` | 제어 흐름 탈취 / exit=66 | 탐지 후 차단 (READONLY) / exit=99 | O |
| tc3 경계 | `rodata` | 제어 흐름 탈취 / exit=66 | 탐지 후 차단 (ID) / exit=99 | O |
| victim 정상 | `normal` | 정상 종료 / exit=0 | 정상 종료 / exit=0 | O |
| victim 위반 | `inject` | 제어 흐름 탈취 / exit=66 | 탐지 후 차단 (READONLY) / exit=99 | O |
| victim 경계 | `rodata` | 제어 흐름 탈취 / exit=66 | 탐지 후 차단 (ID) / exit=99 | O |

근거(보호 후 탐지 줄):

- tc1 정상 `normal`: `-`
- tc1 위반 `inject`: `VTINT DETECTED READONLY vfptr=0x00000000100e4eb0 region=[rw-p]`
- tc1 경계 `rodata`: `VTINT DETECTED ID vfptr=0x00000000004020b0 region=[r--p]`
- tc2 정상 `normal`: `-`
- tc2 위반 `inject`: `VTINT DETECTED READONLY vfptr=0x000000000f44bed0 region=[rw-p]`
- tc2 경계 `rodata`: `VTINT DETECTED ID vfptr=0x00000000004020c0 region=[r--p]`
- tc3 정상 `normal`: `-`
- tc3 위반 `inject`: `VTINT DETECTED READONLY vfptr=0x000000000992aeb0 region=[rw-p]`
- tc3 경계 `rodata`: `VTINT DETECTED ID vfptr=0x0000000000402100 region=[r--p]`
- victim 정상 `normal`: `-`
- victim 위반 `inject`: `VTINT DETECTED READONLY vfptr=0x000000000ed4feb0 region=[rw-p]`
- victim 경계 `rodata`: `VTINT DETECTED ID vfptr=0x00000000004020b8 region=[r--p]`
