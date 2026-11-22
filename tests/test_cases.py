"""직접 작성한 테스트케이스 프로그램 × 3사례(정상·위반·경계).

tests/cases/ 안의 `<이름>_main.cpp` 를 **자동으로 찾아서** 전부 테스트한다.
새 테스트케이스는 `<이름>.h`, `<이름>_factory.cpp`, `<이름>_main.cpp` 세 파일만 넣으면 끝
(이 파일은 고칠 필요 없음). 추가 방법: tests/cases/HOW_TO_ADD.md

빌드는 손으로 할 때와 똑같이 tests/cases/build_case.sh 로 한다
→ out/<이름>_vuln (보호 전), out/<이름>_hardened (보호 후) 가 남아서 나중에 직접 확인할 수 있다.
판정 기준은 11주차 고정 사례와 같다.
"""

from __future__ import annotations

import pytest

from conftest import (
    EXIT_DETECTED, EXIT_HIJACKED, EXIT_OK, MSG_DETECTED, MSG_HIJACKED, MSG_NORMAL,
    OUT, TESTS, record, run, sh,
)

CASES = TESTS / "cases"
BUILD = CASES / "build_case.sh"
REPEAT = 5


def find_cases() -> list[str]:
    """tests/cases/*_main.cpp 에서 테스트케이스 이름을 모은다 (tc1_main.cpp → tc1)."""
    return sorted(p.name[: -len("_main.cpp")] for p in CASES.glob("*_main.cpp"))


CASE_NAMES = find_cases()


@pytest.fixture(scope="module", params=CASE_NAMES, ids=CASE_NAMES)
def program(request, pipeline):
    """테스트케이스 하나를 build_case.sh 로 빌드 + VTint 적용."""
    name = request.param
    sh("bash", BUILD, name)
    return {"id": name, "normal": MSG_NORMAL, "plain": OUT / f"{name}_vuln", "vtint": OUT / f"{name}_hardened"}


def test_case_files_complete():
    """테스트케이스마다 세 파일(.h / _factory.cpp / _main.cpp)이 다 있는지."""
    assert CASE_NAMES, "tests/cases/ 에 *_main.cpp 가 하나도 없음"
    for name in CASE_NAMES:
        for suffix in (".h", "_factory.cpp", "_main.cpp"):
            assert (CASES / f"{name}{suffix}").is_file(), f"{name}{suffix} 없음"


def _run_repeat(binary, mode, name):
    results = [run(binary, mode, log_name=name if i == 0 else None) for i in range(REPEAT)]
    verdicts = [r.verdict for r in results]
    assert len(set(verdicts)) == 1, f"실행마다 판정이 다름: {verdicts}"
    return results[0]


def _clean(res):
    assert not res.timed_out, "시간 초과"
    assert res.signal is None, f"시그널로 종료: {res.signal}\n{res.output}"


# ---------------------------------------------------------------------------
# 정상
# ---------------------------------------------------------------------------
def test_normal_before_and_after(program):
    """정상: 보호 전·후 모두 성공 출력, 종료 0, 탐지·탈취 없음, 출력 동일."""
    before = _run_repeat(program["plain"], "normal", f"{program['id']}_normal_plain")
    after = _run_repeat(program["vtint"], "normal", f"{program['id']}_normal_vtint")
    record(f"{program['id']} 정상", "normal", "plain", before, "정상 종료")
    record(f"{program['id']} 정상", "normal", "vtint", after, "정상 종료")
    for res in (before, after):
        _clean(res)
        assert res.exit_code == EXIT_OK, res.output
        assert program["normal"] in res.stdout
        assert MSG_DETECTED not in res.output
        assert MSG_HIJACKED not in res.output
    assert after.stdout == before.stdout, "보호가 정상 출력을 바꿈"


# ---------------------------------------------------------------------------
# 위반 (vtable injection → READONLY)
# ---------------------------------------------------------------------------
def test_inject_before_hijacked(program):
    """위반, 보호 전: 공격 성공(HIJACKED, 66)."""
    res = _run_repeat(program["plain"], "inject", f"{program['id']}_inject_plain")
    record(f"{program['id']} 위반", "inject", "plain", res, "제어 흐름 탈취")
    _clean(res)
    assert res.exit_code == EXIT_HIJACKED, res.output
    assert MSG_HIJACKED in res.stdout


def test_inject_after_readonly(program):
    """위반, 보호 후: READONLY 탐지(99), HIJACKED 없음, vfptr == 유출된 가짜 vtable 주소."""
    res = _run_repeat(program["vtint"], "inject", f"{program['id']}_inject_vtint")
    record(f"{program['id']} 위반", "inject", "vtint", res, "탐지 후 차단 (READONLY)")
    _clean(res)
    assert res.exit_code == EXIT_DETECTED, res.output
    assert MSG_HIJACKED not in res.output
    assert res.detections, f"탐지 줄 형식 불일치:\n{res.output}"
    det = res.detections[0]
    assert det["kind"] == "READONLY", f"READONLY 로 걸려야 함 (실제 {det['kind']})"
    assert det["region"] and det["region"][1] == "w", f"쓰기 가능 영역이어야 함 (region={det['region']})"
    assert "fake_vtable" in res.leaks, "[leak] fake vtable 줄 없음"
    assert det["vfptr"] == res.leaks["fake_vtable"], f"{det['vfptr']:#x} != {res.leaks['fake_vtable']:#x}"


# ---------------------------------------------------------------------------
# 경계 (.rodata 재사용 → READONLY 통과, ID 탈락)
# ---------------------------------------------------------------------------
def test_rodata_before_hijacked(program):
    """경계, 보호 전: 공격 성공(HIJACKED, 66)."""
    res = _run_repeat(program["plain"], "rodata", f"{program['id']}_rodata_plain")
    record(f"{program['id']} 경계", "rodata", "plain", res, "제어 흐름 탈취")
    _clean(res)
    assert res.exit_code == EXIT_HIJACKED, res.output
    assert MSG_HIJACKED in res.stdout


def test_rodata_after_id(program):
    """경계, 보호 후: READONLY 통과 후 ID 탐지(99), vfptr == 유출된 .rodata 주소."""
    res = _run_repeat(program["vtint"], "rodata", f"{program['id']}_rodata_vtint")
    record(f"{program['id']} 경계", "rodata", "vtint", res, "탐지 후 차단 (ID)")
    _clean(res)
    assert res.exit_code == EXIT_DETECTED, res.output
    assert MSG_HIJACKED not in res.output
    kinds = [d["kind"] for d in res.detections]
    assert kinds == ["ID"], f"ID 한 줄로만 걸려야 함 (READONLY 통과): {kinds}\n{res.output}"
    det = res.detections[0]
    assert det["region"] == "r--p", f"읽기 전용 영역이어야 함 (region={det['region']})"
    assert "rodata_table" in res.leaks, "[leak] rodata fptr array 줄 없음"
    assert det["vfptr"] == res.leaks["rodata_table"], f"{det['vfptr']:#x} != {res.leaks['rodata_table']:#x}"
