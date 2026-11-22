"""D. 11주차 고정 검증 사례 3종 (수정 금지).

기대 결과는 tests/fixed/fixed_cases.json (11주차 보고서 원문) 에서 읽는다.
판정 기준 구체화 (12주차 피드백 "모호한 판정 기준만 구체화"):
  - 종료 코드 0 / 66 / 99 와 출력 문자열을 함께 본다.
  - 탐지 줄 형식: VTINT DETECTED <READONLY|ID> vfptr=0x<hex> region=[perms]
  - 탐지 줄의 vfptr 이 프로그램이 유출한 주소([leak] 줄)와 같아야 한다.
  - 같은 입력을 REPEAT 번 실행해 판정이 매번 같아야 한다 (ASLR 켠 상태).
  - 시그널 종료·시간 초과는 실패.
"""

from __future__ import annotations

import hashlib
import json

import pytest

from conftest import (
    EXIT_DETECTED, EXIT_HIJACKED, EXIT_OK, MSG_DETECTED, MSG_HIJACKED, MSG_NORMAL,
    TESTS, RunResult, record, run,
)

FIXED = TESTS / "fixed"
CASES = {c["id"]: c for c in json.loads((FIXED / "fixed_cases.json").read_text(encoding="utf-8"))["cases"]}
REPEAT = 5


def _run_repeat(binary, mode, name) -> RunResult:
    results = [run(binary, mode, log_name=name if i == 0 else None) for i in range(REPEAT)]
    verdicts = [r.verdict for r in results]
    assert len(set(verdicts)) == 1, f"실행마다 판정이 다름: {verdicts}"
    return results[0]


def _clean(res: RunResult):
    assert not res.timed_out, "시간 초과"
    assert res.signal is None, f"시그널로 종료: {res.signal}\n{res.output}"


@pytest.mark.parametrize("label", ["plain", "vtint"])
def test_D1_D2_normal(bins, label):
    """정상: 보호 전후 모두 DERIVED RUN, 종료 0, VTINT DETECTED 없음."""
    c = CASES["normal"]
    res = _run_repeat(bins[label], c["input"], f"D_normal_{label}")
    record(f"victim {c['구분']}", c["input"], label, res, c[f"expect_{label}"])
    _clean(res)
    assert res.exit_code == EXIT_OK, res.output
    assert MSG_NORMAL in res.stdout
    assert MSG_DETECTED not in res.output
    assert MSG_HIJACKED not in res.output


@pytest.mark.parametrize("cid", ["inject", "rodata"])
def test_D3_D5_attack_plain_hijacked(bins, cid):
    """위반·경계, 보호 전: HIJACKED, 종료 66 (공격이 실제로 성립하는지)."""
    c = CASES[cid]
    res = _run_repeat(bins["plain"], c["input"], f"D_{cid}_plain")
    record(f"victim {c['구분']}", c["input"], "plain", res, c["expect_plain"])
    _clean(res)
    assert res.exit_code == EXIT_HIJACKED, res.output
    assert MSG_HIJACKED in res.stdout


def test_D4_inject_vtint_readonly(bins):
    """위반, 보호 후: VTINT DETECTED READONLY + vfptr, 종료 99, HIJACKED 없음."""
    c = CASES["inject"]
    res = _run_repeat(bins["vtint"], c["input"], "D_inject_vtint")
    record(f"victim {c['구분']}", c["input"], "vtint", res, c["expect_vtint"])
    _clean(res)
    assert res.exit_code == EXIT_DETECTED, res.output
    assert MSG_HIJACKED not in res.output
    assert res.detections, f"탐지 줄 형식 불일치:\n{res.output}"
    det = res.detections[0]
    assert det["kind"] == "READONLY"
    assert det["region"] and det["region"][1] == "w", f"region={det['region']} — 쓰기 가능 영역이어야 함"
    assert "fake_vtable" in res.leaks, "[leak] fake vtable 줄 없음"
    assert det["vfptr"] == res.leaks["fake_vtable"], f"{det['vfptr']:#x} != {res.leaks['fake_vtable']:#x}"


def test_D6_rodata_vtint_id(bins):
    """경계, 보호 후: READONLY 통과, VTINT DETECTED ID + vfptr, 종료 99, HIJACKED 없음."""
    c = CASES["rodata"]
    res = _run_repeat(bins["vtint"], c["input"], "D_rodata_vtint")
    record(f"victim {c['구분']}", c["input"], "vtint", res, c["expect_vtint"])
    _clean(res)
    assert res.exit_code == EXIT_DETECTED, res.output
    assert MSG_HIJACKED not in res.output
    kinds = [d["kind"] for d in res.detections]
    assert kinds == ["ID"], f"ID 탐지 한 줄이어야 함: {kinds}\n{res.output}"
    det = res.detections[0]
    assert det["region"] == "r--p", f"region={det['region']} — 읽기 전용 검사를 통과한 영역이어야 함"
    assert "rodata_table" in res.leaks, "[leak] rodata fptr array 줄 없음"
    assert det["vfptr"] == res.leaks["rodata_table"]


def test_D7_fixed_cases_unchanged():
    """고정 사례 파일이 처음 그대로인지 SHA-256 으로 확인."""
    digest, name = (FIXED / "SHA256SUMS").read_text().split()
    actual = hashlib.sha256((FIXED / name.lstrip("*")).read_bytes()).hexdigest()
    assert actual == digest, "fixed_cases.json 이 바뀜 — 고정 사례는 수정 금지"
