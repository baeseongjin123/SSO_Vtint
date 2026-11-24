"""G. 13주차 확장 검증 — 반례 탐색 (고정 사례 3종과 별도 파일).

대상 프로그램: tests/week13/w13_main.cpp (+ w13_factory.cpp, w13.h)
  N_*  정상 입력    → 보호 전·후 출력이 같고, VTINT DETECTED 없음, 종료 0         (오탐 검사)
  K_*  계측 범위    → vptr 을 "진짜 vtable 의 사본"으로 바꿔 호출.
                     보호 전: 사본 내용이 원본과 같으므로 정상 출력·종료 0
                     보호 후: 그 호출이 검사를 거치면 반드시 탐지(99) 돼야 함    (미탐 = 계측 누락)
  L_*  원논문 한계  → 다른 '진짜' vtable 위치를 가리킴. 원논문도 막지 못한다고 밝힌 경우.
                     기대: 보호 후에도 탐지 없음 (한계가 그대로 재현되는지 기록)
  B_*  빌드 옵션    → -O2, PIE 로 빌드한 같은 프로그램에 VTint 적용

기대 결과는 실행 전에 표(EXPECT)로 고정했다. 결과에 맞춰 바꾸지 않는다.
결과 요약은 results/week13_results.md 로 자동 저장된다.
"""

from __future__ import annotations

import subprocess
import sys

import pytest

from conftest import (
    EXIT_DETECTED, EXIT_OK, MSG_DETECTED, MSG_HIJACKED, RESULTS, ROOT, TESTS, compile_cpp, run, sh,
)

W13 = TESTS / "week13"
SRCS = [W13 / "w13_factory.cpp", W13 / "w13_main.cpp"]

# ---------------------------------------------------------------------------
# 실행 전에 적은 기대 결과
#   ("normal", None)          : 보호 후 출력 == 보호 전 출력, 탐지 없음, 종료 0
#   ("detect", "READONLY"|"ID"): 보호 후 종료 99, 해당 검사로 탐지
#   ("limit", None)           : 원논문 한계 — 보호 후에도 탐지 없음 (보호 전과 같은 출력)
# ---------------------------------------------------------------------------
EXPECT = {
    # N: 정상 — 슬롯·호출 형태
    "N_slot1":        ("normal", None, "두 번째 가상 함수(slot 1)"),
    "N_slot3":        ("normal", None, "slot 3"),
    "N_wide20":       ("normal", None, "slot 20 (vtable 오프셋 0xa0, 큰 displacement)"),
    "N_vdtor":        ("normal", None, "delete 로 가상 소멸자 호출"),
    "N_args":         ("normal", None, "인자 5개 가상 호출 (레지스터 보존)"),
    # N: 정상 — 상속 구조
    "N_m3_pb":        ("normal", None, "부모 3개 다중 상속, 2차 vptr"),
    "N_m3_pc":        ("normal", None, "부모 3개 다중 상속, 3차 vptr"),
    "N_vd_vl":        ("normal", None, "가상 상속(다이아몬드), 1차 부모"),
    "N_vd_vr":        ("normal", None, "가상 상속, 2차 부모"),
    "N_vd_vb":        ("normal", None, "가상 상속, 가상 기반 클래스 포인터"),
    "N_abstract":     ("normal", None, "순수 가상 함수가 있는 추상 클래스"),
    "N_static":       ("normal", None, "전역 객체 (상수 초기화 → vptr 이 .data 에 기록됨)"),
    "N_lib_derived":  ("normal", None, "std::runtime_error 상속 클래스의 what()"),
    "N_lib_object":   ("normal", None, "libstdc++ 가 만든 예외 객체의 what() (vtable 이 .so 안)"),
    # N: 정상 — 자원·상태
    "N_threads":      ("normal", None, "스레드 4개 × 가상 호출 200회"),
    "N_small_stack":  ("normal", None, "스택 64KB 스레드에서 가상 호출"),
    "N_fd_exhausted": ("normal", None, "파일 디스크립터가 바닥난 상태에서 가상 호출"),
    "N_many_maps":    ("normal", None, "mmap 3000개 뒤 가상 호출 (maps > 64KB)"),
    "N_fork":         ("normal", None, "fork 후 자식·부모 모두 가상 호출"),
    # K: 계측 범위 (사본 vtable)
    "K_heap_slot0":   ("detect", "READONLY", "slot 0 호출"),
    "K_heap_slot1":   ("detect", "READONLY", "slot 1 호출"),
    "K_heap_slot3":   ("detect", "READONLY", "slot 3 호출"),
    "K_heap_wide20":  ("detect", "READONLY", "slot 20 호출"),
    "K_heap_args":    ("detect", "READONLY", "인자 5개 호출"),
    "K_heap_vdtor":   ("detect", "READONLY", "가상 소멸자 호출"),
    "K_heap_m3_pb":   ("detect", "READONLY", "2차 vptr 호출"),
    "K_heap_m3_pc":   ("detect", "READONLY", "3차 vptr 호출"),
    "K_heap_vd_vr":   ("detect", "READONLY", "가상 상속 2차 vptr 호출"),
    "K_ro_slot0":     ("detect", "ID", "읽기 전용 사본, slot 0"),
    "K_ro_slot1":     ("detect", "ID", "읽기 전용 사본, slot 1"),
    # L: 원논문 한계
    "L_reuse":        ("limit", None, "다른 클래스의 진짜 vtable 재사용 (원논문 한계)"),
    "L_mid":          ("limit", None, "같은 vtable 안의 다른 위치 (원논문 한계)"),
}

_ROWS: list[tuple] = []


@pytest.fixture(scope="module")
def w13(pipeline, tmp_path_factory):
    d = tmp_path_factory.mktemp("w13")
    plain = compile_cpp([*SRCS, f"-I{W13}"], d / "w13_plain")
    hard = d / "w13_hardened"
    out = sh(sys.executable, ROOT / "tools" / "vrewriter.py", plain, hard)
    yield {"plain": plain, "vtint": hard}
    _write_summary()


def _first_line(res, key=None):
    for ln in res.output.splitlines():
        if key is None or key in ln:
            return ln.strip()
    return ""


@pytest.mark.parametrize("mode", list(EXPECT), ids=list(EXPECT))
def test_G_week13(w13, mode):
    kind, check, desc = EXPECT[mode]
    before = run(w13["plain"], mode, log_name=f"G_{mode}_plain")
    after = run(w13["vtint"], mode, log_name=f"G_{mode}_vtint")
    _ROWS.append((mode, desc, kind, check, before, after))

    # 보호 전: 모든 모드가 정상 종료해야 테스트 프로그램이 올바른 것
    assert before.signal is None and before.exit_code == EXIT_OK, f"보호 전부터 비정상: {before.summary()}"
    assert after.signal is None, f"보호 후 크래시 (시그널 {after.signal}) — 정상 동작을 깨뜨림\n{after.output}"
    assert not after.timed_out, "보호 후 시간 초과"
    assert MSG_HIJACKED not in after.output

    if kind in ("normal", "limit"):
        assert MSG_DETECTED not in after.output, f"오탐: {_first_line(after, MSG_DETECTED)}"
        assert after.exit_code == EXIT_OK, after.summary()
        assert after.stdout == before.stdout, "보호 후 출력이 달라짐"
    else:
        assert after.exit_code == EXIT_DETECTED, (
            f"미탐(계측 누락): 보호 후에도 그대로 실행됨 → {_first_line(after)!r}")
        assert after.detections and after.detections[0]["kind"] == check, \
            f"{check} 로 탐지돼야 하는데: {_first_line(after, MSG_DETECTED)}"


# ---------------------------------------------------------------------------
# B: 빌드 옵션 — 지원하지 않는 입력이면 도구가 명확히 거부해야 한다 (조용히 깨진 바이너리 금지)
# ---------------------------------------------------------------------------
BASE_FLAGS = ["-std=c++17", "-g", "-fno-stack-protector", "-U_FORTIFY_SOURCE",
              "-fno-devirtualize", "-fno-devirtualize-speculatively", "-Wl,-z,relro,-z,now", f"-I{W13}"]


def _build(d, name, extra):
    exe = d / name
    sh("g++", *BASE_FLAGS, *extra, "-o", exe, *SRCS)
    return exe


def _rewrite_or_refuse(plain, hard):
    p = subprocess.run([sys.executable, str(ROOT / "tools" / "vrewriter.py"), str(plain), str(hard)],
                       capture_output=True, text=True)
    return p


@pytest.mark.parametrize("opt", ["-O1", "-O2"], ids=["B1_O1", "B2_O2"])
def test_B_optimized_build(pipeline, tmp_path, opt):
    """최적화 빌드: 계측된 호출이 있어야 하고, 사본 vtable 호출은 탐지돼야 한다. 못 하면 도구가 거부해야 한다."""
    plain = _build(tmp_path, "opt", ["-no-pie", "-fno-pie", opt])
    p = _rewrite_or_refuse(plain, tmp_path / "opt_h")
    if p.returncode != 0:
        pytest.skip(f"도구가 {opt} 입력을 명시적으로 거부함 (허용되는 처리): {p.stderr.strip()[-200:]}")
    after = run(tmp_path / "opt_h", "K_heap_slot0", log_name=f"G_B_{opt}_K_heap_slot0")
    assert after.exit_code == EXIT_DETECTED, (
        f"{opt}: 재작성은 '성공'했지만 가상 호출이 하나도 검사되지 않음 → {_first_line(after)!r}")


def test_B3_pie_build(pipeline, tmp_path):
    """PIE 빌드: 지원하지 않으면 거부해야 하고, 재작성했다면 정상 입력이 그대로 동작해야 한다."""
    plain = _build(tmp_path, "pie", ["-pie", "-fPIE", "-O0"])
    p = _rewrite_or_refuse(plain, tmp_path / "pie_h")
    if p.returncode != 0:
        pytest.skip(f"도구가 PIE 를 명시적으로 거부함 (허용되는 처리): {p.stderr.strip()[-200:]}")
    after = run(tmp_path / "pie_h", "N_slot1", log_name="G_B_pie_N_slot1")
    assert after.signal is None and after.exit_code == EXIT_OK, (
        f"PIE: 재작성은 '성공'(exit 0)했지만 결과 바이너리가 정상 입력에서 {after.summary()}")


# ---------------------------------------------------------------------------
def _write_summary():
    if not _ROWS:
        return
    lines = [
        "# 13주차 확장 검증 결과 (자동 생성: tests/test_week13.py)",
        "",
        "| 입력 | 내용 | 기대 | 보호 전 | 보호 후 | 일치 |",
        "|---|---|---|---|---|---|",
    ]
    for mode, desc, kind, check, b, a in _ROWS:
        exp = {"normal": "정상(출력 동일)", "limit": "탐지 없음(원논문 한계)"}.get(kind, f"탐지 {check}")
        def cell(r):
            if r.signal is not None:
                return f"크래시 sig{r.signal}"
            det = r.detections[0] if r.detections else None
            return f"{det['kind']} 탐지 /99 [{det['region']}]" if det else f"{_first_line(r)[:30]} /{r.exit_code}"
        if kind == "detect":
            ok = a.exit_code == EXIT_DETECTED and a.detections and a.detections[0]["kind"] == check
        else:
            ok = a.signal is None and a.exit_code == EXIT_OK and not a.detections and a.stdout == b.stdout
        lines.append(f"| `{mode}` | {desc} | {exp} | {cell(b)} | {cell(a)} | {'O' if ok else '**X**'} |")
    RESULTS.mkdir(parents=True, exist_ok=True)
    (RESULTS / "week13_results.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
