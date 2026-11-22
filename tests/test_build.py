"""A. 재작성 결과물(정적) 검사 + B. 실행 중 메모리 맵 검사.

VRewriter 가 만든 victim_hardened 가 VTint 전제를 만족하는지 본다.
  - vtsec 세그먼트(기본 0x500000): 4KB 정렬, 읽기 전용(R), 첫 8바이트 = ID, vtable 복사본
  - 검사 코드 세그먼트(기본 0x600000): R+X
조교 피드백: "vtsec 앞 ID 공간 확보"(A8), "/proc/self/maps 의 실제 r--p 매핑"(B1).
"""

from __future__ import annotations

import re
import struct
import subprocess
from dataclasses import dataclass
from pathlib import Path

import pytest

from conftest import HARD, VULN, rewrite, require_tool

PAGE = 4096
ID_SIZE = 8


@dataclass
class Segment:
    type: str
    offset: int
    vaddr: int
    filesz: int
    memsz: int
    flags: str


SEG_RE = re.compile(
    r"^\s*(?P<type>\w+)\s+0x(?P<off>[0-9a-f]+)\s+0x(?P<vaddr>[0-9a-f]+)\s+0x[0-9a-f]+\s+"
    r"0x(?P<filesz>[0-9a-f]+)\s+0x(?P<memsz>[0-9a-f]+)\s+(?P<flags>[RWE ]+?)\s+0x[0-9a-f]+\s*$"
)


def _sh(*cmd) -> str:
    require_tool(cmd[0])
    return subprocess.run(list(map(str, cmd)), capture_output=True, text=True, check=True).stdout


def segments(binary: Path) -> list[Segment]:
    segs = []
    for line in _sh("readelf", "-lW", binary).splitlines():
        m = SEG_RE.match(line)
        if m:
            segs.append(Segment(m["type"], int(m["off"], 16), int(m["vaddr"], 16),
                                int(m["filesz"], 16), int(m["memsz"], 16), m["flags"].replace(" ", "")))
    return segs


def seg_at(binary: Path, va: int) -> Segment | None:
    for s in segments(binary):
        if s.type == "LOAD" and s.vaddr <= va < s.vaddr + s.memsz:
            return s
    return None


def read_va(binary: Path, va: int, n: int) -> bytes:
    s = seg_at(binary, va)
    assert s is not None, f"{va:#x} 를 담는 LOAD 세그먼트 없음"
    with open(binary, "rb") as f:
        f.seek(s.offset + (va - s.vaddr))
        return f.read(n)


@pytest.fixture(scope="module")
def meta(pipeline):
    if not pipeline:
        pytest.skip("파이프라인 메타데이터 없음 (VTINT_NO_BUILD 로 실행됨)")
    return {
        "id": int(pipeline["id"], 16),
        "vtsec": int(pipeline["vtsec_va"], 16),
        "code": int(pipeline["code_va"], 16),
        "moved": [(m["name"], int(m["old"], 16), int(m["new"], 16)) for m in pipeline["moved_vtables"]],
        "hooked": pipeline["hooked_vcalls"],
        "refs": pipeline["patched_refs"],
    }


# ---------------------------------------------------------------------------
# A. 정적 검사
# ---------------------------------------------------------------------------
def test_A1_no_pie(pipeline):
    assert re.search(r"Type:\s+EXEC", _sh("readelf", "-hW", HARD)), "보호 바이너리가 no-PIE(EXEC) 아님"


def test_A2_full_relro_kept(pipeline):
    """재작성 후에도 full RELRO(GNU_RELRO + BIND_NOW)가 유지되는지."""
    assert any(s.type == "GNU_RELRO" for s in segments(HARD)), "GNU_RELRO 없음"
    dyn = _sh("readelf", "-dW", HARD)
    assert "BIND_NOW" in dyn or re.search(r"FLAGS(_1)?\)\s+.*\bNOW\b", dyn), "BIND_NOW 없음"


def test_A3_A4_vtsec_segment_aligned(meta):
    s = seg_at(HARD, meta["vtsec"])
    assert s is not None, f"vtsec({meta['vtsec']:#x}) LOAD 세그먼트 없음"
    assert s.vaddr == meta["vtsec"] and s.vaddr % PAGE == 0, f"vtsec 시작 {s.vaddr:#x} 4KB 정렬 아님"


def test_A5_vtsec_readonly(meta):
    flags = seg_at(HARD, meta["vtsec"]).flags
    assert flags == "R", f"vtsec 권한이 {flags} — R(읽기 전용)만 있어야 함"


def test_A6_check_code_segment(meta):
    s = seg_at(HARD, meta["code"])
    assert s is not None, "검사 코드 세그먼트 없음"
    assert s.flags == "RE", f"검사 코드 세그먼트 권한 {s.flags} — R+X 여야 함 (W 금지)"


def test_A7_vtables_copied_into_vtsec(meta):
    """이전된 vtable 이 모두 vtsec 안에 있고, 내용이 원본 .rodata vtable 과 같은지."""
    assert meta["moved"], "이전된 vtable 없음 (ELFParser/BitCover 가 vtable 을 못 찾음)"
    s = seg_at(HARD, meta["vtsec"])
    for name, old, new in meta["moved"]:
        assert s.vaddr <= new < s.vaddr + s.memsz, f"{name} 새 주소 {new:#x} 가 vtsec 밖"
        assert read_va(HARD, new, 24) == read_va(VULN, old, 24), f"{name} 복사본 내용이 원본과 다름"


def test_A7b_expected_classes_moved(meta):
    names = " ".join(n for n, _, _ in meta["moved"])
    for cls in ("Base", "Derived"):
        assert cls in names, f"{cls} vtable 이 이전되지 않음: {names}"


def test_A8_id_space_reserved(meta):
    """조교 피드백: ID 8바이트와 첫 vtable 이 겹치지 않음."""
    first = min(new for _, _, new in meta["moved"])
    assert first >= meta["vtsec"] + ID_SIZE, f"첫 vtable {first:#x} 가 ID 자리와 겹침"


def test_A9_id_written(meta):
    raw = read_va(HARD, meta["vtsec"], ID_SIZE)
    assert raw != b"\0" * ID_SIZE, "ID 가 0"
    assert struct.unpack("<Q", raw)[0] == meta["id"], "vtsec 첫 8바이트가 메타데이터의 ID 와 다름"


def test_A10_id_random_per_rewrite(pipeline, tmp_path):
    """재작성할 때마다 ID 가 달라야 한다 (같은 입력 바이너리로 두 번 재작성)."""
    ids = {rewrite(VULN, tmp_path / f"h{i}")["id"] for i in range(2)}
    assert len(ids) == 2, f"두 번 재작성한 ID 가 같음: {ids}"


def test_A11_plain_untouched(meta):
    assert seg_at(VULN, meta["vtsec"]) is None, "보호 전 바이너리에도 vtsec 주소에 세그먼트가 있음"


def test_A12_every_vtable_page_has_id(meta):
    """vtable 이 걸친 모든 4KB 페이지 시작에 ID 가 있어야 함 (vtsec 이 4KB 를 넘으면 오탐 위험)."""
    ident = struct.pack("<Q", meta["id"])
    pages = {new & ~(PAGE - 1) for _, _, new in meta["moved"]}
    bad = [hex(p) for p in sorted(pages) if read_va(HARD, p, ID_SIZE) != ident]
    assert not bad, f"ID 없는 vtable 페이지: {bad}"


def test_A13_instrumented(meta):
    """가상 호출 계측과 생성자 참조 패치가 실제로 일어났는지."""
    assert meta["hooked"] >= 1, "계측된 가상 호출 0개"
    assert meta["refs"] >= 1, "패치된 vtable 참조 0개"


# ---------------------------------------------------------------------------
# B. 실행 중 메모리 맵 (gdb)
# ---------------------------------------------------------------------------
MAPS_RE = re.compile(r"^([0-9a-f]+)-([0-9a-f]+)\s+(\S{4})\s", re.MULTILINE)
PY_MAPS = (
    "python import gdb; print('MAPS_BEGIN'); "
    "print(open('/proc/%d/maps' % gdb.selected_inferior().pid).read()); print('MAPS_END')"
)


def gdb_maps(binary: Path, mode: str, stop: list[str]):
    """stop 명령(브레이크/캐치)에서 멈춘 뒤 /proc/<pid>/maps 를 읽는다."""
    require_tool("gdb")
    cmd = ["gdb", "-q", "-nx", "-batch", "-ex", "set pagination off", "-ex", "set confirm off"]
    for s in stop:
        cmd += ["-ex", s]
    cmd += ["-ex", f"run {mode}", "-ex", PY_MAPS, "-ex", "kill", str(binary)]
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    out = p.stdout + p.stderr
    if "MAPS_BEGIN" not in out:
        pytest.skip(f"gdb 로 maps 를 못 읽음 (Docker 는 --cap-add=SYS_PTRACE 필요):\n{out[-1200:]}")
    body = out.split("MAPS_BEGIN", 1)[1].split("MAPS_END", 1)[0]
    return out, [(int(a, 16), int(b, 16), pr) for a, b, pr in MAPS_RE.findall(body)]


def perms_of(maps, addr):
    return next((pr for a, b, pr in maps if a <= addr < b), None)


def test_B1_vtsec_mapped_r__p(meta):
    """조교 피드백: 정상 실행 중(Derived::run 진입 시) vtsec 이 실제로 r--p."""
    _, maps = gdb_maps(HARD, "normal", ["break Derived::run"])
    assert perms_of(maps, meta["vtsec"]) == "r--p"


def test_B2_check_code_mapped_r_xp(meta):
    _, maps = gdb_maps(HARD, "normal", ["break Derived::run"])
    assert perms_of(maps, meta["code"]) == "r-xp"


def _at_exit(mode, leak_text):
    # 검사 루틴은 raw syscall exit(60) 으로 끝나므로 그 순간을 잡는다
    out, maps = gdb_maps(HARD, mode, ["catch syscall exit", "catch syscall exit_group"])
    m = re.search(leak_text + r" @ (0x[0-9a-f]+)", out)
    if not m:
        pytest.skip("gdb 출력에 [leak] 줄 없음")
    return int(m.group(1), 16), maps


def test_B3_fake_vtable_is_writable(pipeline):
    """위반 사례의 전제: 가짜 vtable 이 rw-p 영역(힙)."""
    addr, maps = _at_exit("inject", r"\[leak\] fake vtable")
    perms = perms_of(maps, addr)
    assert perms and perms.startswith("rw"), f"{addr:#x} 권한 {perms}"


def test_B4_rodata_table_is_r__p(pipeline):
    """경계 사례의 전제: .rodata 함수 포인터 배열이 r--p."""
    addr, maps = _at_exit("rodata", r"\[leak\] rodata fptr array")
    assert perms_of(maps, addr) == "r--p"
