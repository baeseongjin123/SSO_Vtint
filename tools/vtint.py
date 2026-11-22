#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
VTint 오케스트레이터 (명령행 도구)

  exe  ──► ELFParser ──► BitCover ──► VRewriter ──► 보호 바이너리
                                                       │
            입력(시나리오)을 보호 전/후 바이너리에 차례로 넣어 판정·근거 출력

사용:
  python3 tools/vtint.py pipeline <vuln_exe> [out_hardened]   # 3단계만 수행
  python3 tools/vtint.py judge <exe> <mode>                   # 한 번 실행·판정
  python3 tools/vtint.py demo [--build]                       # 전체 데모(비교표)
"""
import sys, os, json, subprocess, argparse

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, ".."))
sys.path.insert(0, HERE)

import elfparser, bitcover, vrewriter

MODES = ["normal", "inject", "rodata"]
EXPECT = {  # (보호 전, 보호 후) 기대 판정
    "normal": ("정상 종료", "정상 종료"),
    "inject": ("제어흐름 탈취", "탐지·차단(READONLY)"),
    "rodata": ("제어흐름 탈취", "탐지·차단(ID)"),
}


# ---- 실행·판정 -------------------------------------------------------------
def judge(exe, mode):
    try:
        pr = subprocess.run([exe, mode], capture_output=True, text=True, timeout=10)
    except Exception as e:
        return {"verdict": "실행오류", "detail": str(e), "rc": None, "out": ""}
    out = (pr.stdout or "") + (pr.stderr or "")
    rc = pr.returncode
    if "VTINT DETECTED" in out:
        # VTINT DETECTED <which> vfptr=0x.. region=[..]
        line = [l for l in out.splitlines() if "VTINT DETECTED" in l][0]
        which = line.split()[2] if len(line.split()) > 2 else "?"
        return {"verdict": "탐지·차단(%s)" % which, "detail": line.strip(), "rc": rc, "out": out}
    if "HIJACKED" in out:
        return {"verdict": "제어흐름 탈취", "detail": "HIJACKED (공격자 함수 실행)", "rc": rc, "out": out}
    if rc == 0 and "DERIVED RUN" in out:
        return {"verdict": "정상 종료", "detail": "DERIVED RUN", "rc": rc, "out": out}
    return {"verdict": "기타", "detail": out.strip()[:80], "rc": rc, "out": out}


# ---- 3단계 파이프라인 -------------------------------------------------------
def pipeline(vuln_exe, out_hardened, verbose=True):
    # 1) ELFParser
    p = elfparser.ELFParser(vuln_exe)
    pr = p.result()
    if verbose:
        print("┌─ [1] ELFParser ─ ELF 파싱 · 후보 vtable 식별")
        for v in pr["candidate_vtables"]:
            print("│   후보 vtable %-14s @0x%x  (addr_point 0x%x, slot0=0x%x)"
                  % (v["name"], v["vaddr"], v["addr_point"], v["entries"][0]))
    # 2) BitCover
    cov = bitcover.run(vuln_exe)
    if verbose:
        print("├─ [2] BitCover ─ 디스어셈블 · 가상호출/참조 식별")
        for s in cov["vcall_sites"]:
            print("│   가상호출 @0x%x  (%s)  계측윈도우 @0x%x %dB"
                  % (s["call_vaddr"], s["call_text"], s["window_vaddr"], s["window_len"]))
        print("│   vtable 참조 %d곳(생성자 vfptr 대입) 패치 예정" % len(cov["vref_sites"]))
    # 3) VRewriter
    rw = vrewriter.VRewriter(vuln_exe, cov, os.path.join(ROOT, "runtime"))
    meta = rw.rewrite(out_hardened)
    if verbose:
        print("└─ [3] VRewriter ─ vtsec 이전 · ID · 트램펄린 삽입")
        print("    ID=%s  vtsec=%s  code=%s" % (meta["id"], meta["vtsec_va"], meta["code_va"]))
        for m in meta["moved_vtables"]:
            print("    이전 %-14s %s → %s" % (m["name"], m["old"], m["new"]))
        print("    보호 바이너리: %s" % out_hardened)
    return pr, cov, meta


# ---- 데모(비교표) -----------------------------------------------------------
def demo(do_build):
    out = os.path.join(ROOT, "out")
    os.makedirs(out, exist_ok=True)
    vuln = os.path.join(out, "victim_vuln")
    hard = os.path.join(out, "victim_hardened")

    if do_build or not os.path.exists(vuln):
        print("# 취약 바이너리 컴파일 …")
        subprocess.check_call(["bash", os.path.join(ROOT, "tests", "build.sh")])
        print()

    print("# VTint 파이프라인 (exe → PEParser[ELF] → BitCover → VRewriter)\n")
    pipeline(vuln, hard)
    print()

    # 보호 전/후 실행·판정
    rows = []
    for mode in MODES:
        bj = judge(vuln, mode)
        aj = judge(hard, mode)
        rows.append((mode, bj, aj))

    # 표 출력
    print("\n# 검증 사례 · 보호 전/후 판정표\n")
    print("  %-7s │ %-28s │ %-34s │ 결과" % ("시나리오", "보호 전 (victim_vuln)", "보호 후 (victim_hardened)"))
    print("  " + "─" * 7 + "─┼─" + "─" * 28 + "─┼─" + "─" * 34 + "─┼────")
    allok = True
    for (mode, bj, aj) in rows:
        exp_b, exp_a = EXPECT[mode]
        ok = bj["verdict"] == exp_b and aj["verdict"] == exp_a
        allok = allok and ok
        print("  %-7s │ %-28s │ %-34s │ %s"
              % (mode, "%s(rc=%s)" % (bj["verdict"], bj["rc"]),
                 "%s(rc=%s)" % (aj["verdict"], aj["rc"]), "✔" if ok else "✗"))
    print()
    # 근거 상세
    print("# 판정 근거(보호 후)\n")
    for (mode, bj, aj) in rows:
        print("  [%s]" % mode)
        print("    보호 전: %s" % bj["detail"])
        print("    보호 후: %s" % aj["detail"])
    print()
    print("종합: %s" % ("모든 시나리오 기대 결과와 일치 ✔" if allok else "불일치 발생 ✗"))
    return 0 if allok else 1


def main():
    ap = argparse.ArgumentParser(prog="vtint")
    sub = ap.add_subparsers(dest="cmd")

    pp = sub.add_parser("pipeline"); pp.add_argument("vuln"); pp.add_argument("out", nargs="?")
    jp = sub.add_parser("judge"); jp.add_argument("exe"); jp.add_argument("mode")
    dp = sub.add_parser("demo"); dp.add_argument("--build", action="store_true")

    args = ap.parse_args()
    if args.cmd == "pipeline":
        out = args.out or (args.vuln + "_hardened")
        pipeline(args.vuln, out)
    elif args.cmd == "judge":
        r = judge(args.exe, args.mode)
        print("판정: %s" % r["verdict"])
        print("근거: %s" % r["detail"])
        print("종료코드: %s" % r["rc"])
    elif args.cmd == "demo":
        sys.exit(demo(args.build))
    else:
        ap.print_help()


if __name__ == "__main__":
    main()
