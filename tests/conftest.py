"""VTint 테스트 공통 설정 (pytest).

구현(바이너리 재작성 방식)과의 인터페이스:
  - 보호 전: out/victim_vuln          (tests/build.sh 로 컴파일)
  - 보호 후: out/victim_hardened      (tools/vrewriter.py 로 재작성)
  - 입력:    argv[1] = normal | inject | rodata
  - 출력:    DERIVED RUN / HIJACKED (stdout),
             VTINT DETECTED <READONLY|ID> vfptr=0x... region=[perms] (stderr)
             [leak] fake vtable @ 0x... / [leak] rodata fptr array @ 0x... (stdout)
  - 종료 코드: 0 정상, 66 탈취, 99 탐지

세션 시작 시 한 번 build.sh + vrewriter 를 실행해 바이너리를 새로 만든다
(VTINT_NO_BUILD=1 이면 이미 있는 out/ 바이너리를 그대로 씀).
"""

from __future__ import annotations

import json
import os
import platform
import re
import shutil
import signal
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
TESTS = ROOT / "tests"
OUT = ROOT / "out"
RESULTS = ROOT / "results"
LOGS = RESULTS / "logs"

VULN = OUT / "victim_vuln"
HARD = OUT / "victim_hardened"

EXIT_OK, EXIT_HIJACKED, EXIT_DETECTED = 0, 66, 99
MSG_NORMAL, MSG_HIJACKED, MSG_DETECTED = "DERIVED RUN", "HIJACKED", "VTINT DETECTED"

RUN_TIMEOUT = float(os.environ.get("VTINT_TIMEOUT", "10"))

# tests/build.sh 와 같은 컴파일 옵션 (테스트용 추가 프로그램에도 똑같이 적용)
CXXFLAGS = [
    "-std=c++17", "-O0", "-g", "-no-pie", "-fno-pie",
    "-fno-stack-protector", "-U_FORTIFY_SOURCE",
    "-fno-devirtualize", "-fno-devirtualize-speculatively",
    "-Wl,-z,relro,-z,now",
]

DETECT_RE = re.compile(
    r"VTINT DETECTED (?P<kind>READONLY|ID)\s+vfptr=(?P<addr>0x[0-9a-fA-F]+)"
    r"(?:\s+region=\[?(?P<region>[^\]\s]+)\]?)?"
)
LEAK_RES = {
    "fake_vtable": re.compile(r"\[leak\] fake vtable @ (0x[0-9a-fA-F]+)"),
    "rodata_table": re.compile(r"\[leak\] rodata fptr array @ (0x[0-9a-fA-F]+)"),
}


# ---------------------------------------------------------------------------
# 실행
# ---------------------------------------------------------------------------
@dataclass
class RunResult:
    cmd: list[str]
    exit_code: int | None
    signal: int | None
    stdout: str
    stderr: str
    timed_out: bool = False
    detections: list[dict] = field(default_factory=list)
    leaks: dict[str, int] = field(default_factory=dict)

    @property
    def output(self) -> str:
        return self.stdout + self.stderr

    @property
    def verdict(self) -> str:
        if self.timed_out:
            return "시간 초과"
        if self.signal is not None:
            return f"시그널 {signal.Signals(self.signal).name}"
        if self.exit_code == EXIT_DETECTED and self.detections:
            return f"탐지 후 차단 ({self.detections[0]['kind']})"
        if self.exit_code == EXIT_HIJACKED and MSG_HIJACKED in self.stdout:
            return "제어 흐름 탈취"
        if self.exit_code == EXIT_OK and MSG_NORMAL in self.stdout and not self.detections:
            return "정상 종료"
        return f"기타 (종료 코드 {self.exit_code})"

    def summary(self) -> str:
        code = self.exit_code if self.signal is None else f"sig{self.signal}"
        return f"{self.verdict} / exit={code}"


def run(binary: Path, *args, timeout: float = RUN_TIMEOUT, log_name: str | None = None) -> RunResult:
    cmd = [str(binary), *map(str, args)]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, errors="replace", timeout=timeout)
        rc = p.returncode
        res = RunResult(cmd, rc if rc >= 0 else None, -rc if rc < 0 else None, p.stdout, p.stderr)
    except subprocess.TimeoutExpired as e:
        dec = lambda b: b.decode(errors="replace") if isinstance(b, bytes) else (b or "")
        res = RunResult(cmd, None, None, dec(e.stdout), dec(e.stderr), timed_out=True)
    res.detections = [
        {"kind": m["kind"], "vfptr": int(m["addr"], 16), "region": m["region"]}
        for m in DETECT_RE.finditer(res.output)
    ]
    res.leaks = {k: int(m.group(1), 16) for k, r in LEAK_RES.items() if (m := r.search(res.output))}
    if log_name:
        save_log(log_name, res)
    return res


def save_log(name: str, res: RunResult) -> None:
    LOGS.mkdir(parents=True, exist_ok=True)
    safe = re.sub(r"[^\w.-]+", "_", name)
    (LOGS / f"{safe}.log").write_text(
        f"$ {' '.join(res.cmd)}\nexit_code: {res.exit_code}\nsignal: {res.signal}\n"
        f"timed_out: {res.timed_out}\nverdict: {res.verdict}\n"
        f"--- stdout ---\n{res.stdout}\n--- stderr ---\n{res.stderr}\n",
        encoding="utf-8",
    )


def require_tool(tool: str) -> str:
    path = shutil.which(tool)
    if not path:
        pytest.skip(f"'{tool}' 명령이 없음")
    return path


def sh(*cmd, cwd=ROOT) -> str:
    p = subprocess.run(list(map(str, cmd)), cwd=cwd, capture_output=True, text=True)
    if p.returncode != 0:
        pytest.fail(f"명령 실패: {' '.join(map(str, cmd))}\n{p.stdout}\n{p.stderr}")
    return p.stdout


def rewrite(vuln: Path, hardened: Path) -> dict:
    """VRewriter 를 실행하고 메타데이터(JSON)를 돌려준다."""
    out = sh(sys.executable, ROOT / "tools" / "vrewriter.py", vuln, hardened)
    return json.loads(out[out.index("{"): out.rindex("}") + 1])


def compile_cpp(sources: list[Path], out: Path) -> Path:
    require_tool("g++")
    sh("g++", *CXXFLAGS, "-o", out, *sources)
    return out


# ---------------------------------------------------------------------------
# fixture
# ---------------------------------------------------------------------------
@pytest.fixture(scope="session")
def pipeline() -> dict:
    """victim_vuln 빌드 → VRewriter → victim_hardened. 메타데이터 반환."""
    meta_path = OUT / "pipeline_meta.json"
    if os.environ.get("VTINT_NO_BUILD") == "1":
        if not (VULN.is_file() and HARD.is_file()):
            pytest.skip("VTINT_NO_BUILD=1 인데 out/ 바이너리가 없음")
        return json.loads(meta_path.read_text()) if meta_path.is_file() else {}
    sh("bash", TESTS / "build.sh")
    meta = rewrite(VULN, HARD)
    meta_path.write_text(json.dumps(meta, indent=2, ensure_ascii=False))
    return meta


@pytest.fixture(scope="session")
def bins(pipeline) -> dict[str, Path]:
    return {"plain": VULN, "vtint": HARD}


# ---------------------------------------------------------------------------
# 전·후 비교표 (results/before_after.md)
# ---------------------------------------------------------------------------
_COMPARISON: dict[tuple[str, str], dict] = {}


def record(case: str, inp: str, label: str, res: RunResult, expected: str) -> None:
    row = _COMPARISON.setdefault((case, inp), {"expect": {}})
    row[label] = res
    row["expect"][label] = expected


def pytest_sessionfinish(session, exitstatus):
    RESULTS.mkdir(parents=True, exist_ok=True)
    _write_env()
    if not _COMPARISON:
        return
    lines = [
        "# 보호 적용 전·후 결과 비교",
        "",
        "`./test.sh` 실행 시 자동 생성. victim = 팀원 예제(11주차 고정 사례), tc1~ = 직접 만든 테스트케이스. 로그 원본: `results/logs/`",
        "",
        "| 구분 | 입력 | 보호 전 (판정 / 종료 코드) | 보호 후 (판정 / 종료 코드) | 기대 일치 |",
        "|---|---|---|---|---|",
    ]
    for (case, inp), row in _COMPARISON.items():
        cells, ok = [], True
        for label in ("plain", "vtint"):
            res = row.get(label)
            if res is None:
                cells.append("미실행")
                ok = False
            else:
                cells.append(res.summary())
                ok &= res.verdict == row["expect"][label]
        lines.append(f"| {case} | `{inp}` | {cells[0]} | {cells[1]} | {'O' if ok else 'X'} |")
    lines += ["", "근거(보호 후 탐지 줄):", ""]
    for (case, inp), row in _COMPARISON.items():
        res = row.get("vtint")
        det = next((ln for ln in res.output.splitlines() if MSG_DETECTED in ln), "-") if res else "-"
        lines.append(f"- {case} `{inp}`: `{det}`")
    (RESULTS / "before_after.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def _write_env() -> None:
    def ver(cmd):
        try:
            out = subprocess.run(cmd, capture_output=True, text=True, timeout=5).stdout.strip()
            return out.splitlines()[0] if out else "?"
        except Exception:
            return "없음"

    def mod(name):
        try:
            return __import__(name).__version__
        except Exception:
            return "없음"

    info = {
        "os": platform.platform(),
        "python": platform.python_version(),
        "pytest": pytest.__version__,
        "lief": mod("lief"),
        "capstone": mod("capstone"),
        "g++": ver(["g++", "--version"]),
        "gdb": ver(["gdb", "--version"]),
    }
    (RESULTS / "env.txt").write_text("".join(f"{k}: {v}\n" for k, v in info.items()), encoding="utf-8")
