"""E. 오탐 0건 묶음 (성공 기준: 다중 상속 포함 정상 입력에서 오탐 0건).

victim 은 Base/Derived 만 있으므로, 11주차 기능 1 구성(Base/Derived/Other/Multi)을 담은
정상 프로그램(tests/progs)을 build.sh 와 같은 옵션으로 컴파일 → VRewriter 로 재작성한 뒤
보호 전·후 결과가 같고 VTINT DETECTED 가 없는지 본다. VTint 를 '입력 바이너리를 받는 도구'로 시험하는 셈.
"""

from __future__ import annotations

import pytest

from conftest import EXIT_OK, MSG_DETECTED, MSG_HIJACKED, TESTS, compile_cpp, rewrite, run

PROGS = TESTS / "progs"


@pytest.fixture(scope="module")
def fp_bins(pipeline, tmp_path_factory):
    d = tmp_path_factory.mktemp("fp")
    plain = compile_cpp([PROGS / "fp_factory.cpp", PROGS / "fp_main.cpp"], d / "fp_plain")
    meta = rewrite(plain, d / "fp_hardened")
    return {"plain": plain, "vtint": d / "fp_hardened", "meta": meta}


@pytest.fixture(scope="module")
def many_bins(pipeline, tmp_path_factory):
    d = tmp_path_factory.mktemp("many")
    plain = compile_cpp([PROGS / "fp_many.cpp"], d / "many_plain")
    meta = rewrite(plain, d / "many_hardened")
    return {"plain": plain, "vtint": d / "many_hardened", "meta": meta}


def _same_and_clean(b, mode, name, timeout=10):
    before = run(b["plain"], mode, log_name=f"{name}_plain", timeout=timeout)
    after = run(b["vtint"], mode, log_name=f"{name}_vtint", timeout=timeout)
    assert before.exit_code == EXIT_OK, f"보호 전부터 비정상: {before.summary()}"
    assert after.signal is None and not after.timed_out, f"보호 후 크래시: {after.summary()}\n{after.output}"
    assert MSG_DETECTED not in after.output, f"오탐:\n{after.output}"
    assert MSG_HIJACKED not in after.output
    assert after.exit_code == EXIT_OK, after.summary()
    assert after.stdout == before.stdout, "보호 후 출력이 달라짐"


@pytest.mark.parametrize(
    "mode",
    ["base", "derived", "other", "multi", "multi_base2"],
    ids=["E1_base", "E1_derived", "E1_other", "E2_multi", "E2_multi_base2"],
)
def test_E1_E2_classes(fp_bins, mode):
    """E1/E2: 클래스별 정상 가상 호출 (E2 는 다중 상속, multi_base2 는 2차 vptr)."""
    _same_and_clean(fp_bins, mode, f"E_{mode}")


def test_E3_repeat_calls(fp_bins):
    """E3: 같은 객체에 가상 호출 1000회."""
    _same_and_clean(fp_bins, "repeat", "E3_repeat", timeout=60)


def test_E4_victim_normal_same_output(bins):
    """E4: 고정 사례 victim 의 정상 입력 출력이 보호 전·후 같음."""
    _same_and_clean(bins, "normal", "E4_victim_normal")


@pytest.mark.parametrize("mode", ["first", "last", "all"], ids=["E5_first", "E5_last", "E5_all"])
def test_E5_vtsec_over_4kb(many_bins, mode):
    """E5: vtable 200개로 vtsec 이 4KB 를 넘을 때 (ID 가 첫 페이지에만 있으면 last/all 에서 오탐)."""
    _same_and_clean(many_bins, mode, f"E5_{mode}")
