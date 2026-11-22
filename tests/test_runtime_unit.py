"""C. 검사 루틴 단위 테스트.

runtime/vtint_check.c 를 VRewriter 와 같은 옵션으로 컴파일해 tests/unit/check_harness.c 와 링크하고,
케이스마다 subprocess 로 실행한다 (실패 경로가 exit(99) 라서 한 프로세스에 한 케이스).

판정: 종료 코드 + 탐지 줄 형식 + 탐지 줄 vfptr == 하네스가 출력한 ADDR.
"""

from __future__ import annotations

import re

import pytest

from conftest import EXIT_DETECTED, EXIT_OK, MSG_DETECTED, ROOT, TESTS, require_tool, run, sh

TEST_ID = 0x1122334455667788
ADDR_RE = re.compile(r"^ADDR=(0x[0-9a-fA-F]+|0)\s*$", re.MULTILINE)

# VRewriter.build_check_blob 과 같은 컴파일 옵션
CHECK_CFLAGS = [
    "-ffreestanding", "-fno-pic", "-fno-pie", "-fno-stack-protector",
    "-fcf-protection=none", "-fno-asynchronous-unwind-tables",
    "-fno-builtin", "-fno-tree-loop-distribute-patterns", "-Os",
]


@pytest.fixture(scope="module")
def harness(tmp_path_factory):
    require_tool("gcc")
    d = tmp_path_factory.mktemp("unit")
    obj = d / "check.o"
    sh("gcc", f"-DVTINT_ID={TEST_ID:#x}UL", *CHECK_CFLAGS, "-c", ROOT / "runtime" / "vtint_check.c", "-o", obj)
    exe = d / "check_harness"
    sh("gcc", "-O0", "-no-pie", "-fno-pie", f"-DVTINT_ID={TEST_ID:#x}UL",
       TESTS / "unit" / "check_harness.c", obj, "-o", exe)
    return exe


# (ID, 케이스, 기대)  기대 = "PASS" 또는 탐지 종류
CASES = [
    ("C1", "ro_id", "PASS"),              # 읽기 전용 + 페이지 선두 ID 일치
    ("C2", "ro_id_page_end", "PASS"),     # 같은 페이지 끝부분
    ("C3", "heap", "READONLY"),
    ("C4", "stack", "READONLY"),
    ("C5", "data", "READONLY"),           # 쓰기 가능 전역
    ("C6", "rodata", "ID"),               # 읽기 전용이지만 ID 없음 (경계 사례의 단위판)
    ("C7", "code", "ID"),                 # r-x, ID 없음
    ("C8", "null", "READONLY"),           # 매핑 없음 → 크래시 없이 READONLY(unmapped)
    ("C9", "unmapped", "READONLY"),
    ("C10", "rw_with_id", "READONLY"),    # ID 를 알아도 쓰기 가능 영역이면 차단
    ("C11", "ro_wrong_id", "ID"),
    ("C12", "rx_with_id", "PASS"),        # 쓰기 불가 + ID 일치면 통과 (정책 확인용)
    ("C13", "second_page", "ID"),         # 검사는 페이지 선두만 봄 → 재작성기가 페이지마다 ID 를 써야 함
]


def _addr(stdout):
    found = ADDR_RE.findall(stdout)
    return int(found[-1], 16) if found else None


def _check(res, expect):
    assert not res.timed_out, "시간 초과"
    assert res.signal is None, f"검사 중 시그널로 죽음({res.signal}) — 크래시 없이 판정해야 함\n{res.output}"
    if expect == "PASS":
        assert res.exit_code == EXIT_OK, f"오탐: {res.summary()}\n{res.output}"
        assert "PASS" in res.stdout and MSG_DETECTED not in res.output
        return
    assert res.exit_code == EXIT_DETECTED, f"미탐: {res.summary()}\n{res.output}"
    assert "PASS" not in res.stdout
    assert res.detections, f"탐지 줄 형식 불일치:\n{res.output}"
    det = res.detections[0]
    assert det["kind"] == expect, f"{expect} 로 걸려야 하는데 {det['kind']}"
    assert det["vfptr"] == _addr(res.stdout), f"탐지 vfptr {det['vfptr']:#x} != 넘긴 주소"


@pytest.mark.parametrize("tid,case,expect", CASES, ids=[f"{t}_{c}" for t, c, _ in CASES])
def test_check_routine(harness, tid, case, expect):
    _check(run(harness, case, log_name=f"{tid}_{case}"), expect)


def test_C14_big_maps_no_false_positive(harness):
    """[13주차 반례 후보] /proc/self/maps 가 64KB(검사 루틴 버퍼)를 넘을 때.

    정상 vtable 페이지가 maps 뒤쪽에 있으면 버퍼에서 잘려 '매핑 없음 → READONLY' 오탐이 날 수 있다.
    """
    _check(run(harness, "big_maps", log_name="C14_big_maps"), "PASS")
