#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
VRewriter  (논문의 VRewriter 를 ELF 에 대응)

역할: BitCover 결과를 받아 원본 ELF 를 '실제로 재작성' 하여 보호 바이너리를 만든다.
  1. 읽기 전용 새 세그먼트 vtsec(0x500000) 생성
       - 페이지 선두 8바이트에 랜덤 ID 기록
       - 확정된 vtable 들을 그대로 복사(이전)
  2. 검사 코드 세그먼트(0x600000, R+X) 생성
       - freestanding 검사 루틴(vtint_check.c)을 ID 박아 컴파일·주입
       - 가상 호출마다 트램펄린 생성
  3. 코드 패치
       - 생성자의 vtable 참조(immediate)를 vtsec 의 새 주소점으로 교체
       - 가상 호출 계측 윈도우를 트램펄린으로 detour(jmp rel32)

트램펄린(가상 호출 직전):
     <base load>            ; rBASE = vtable base
     push rBASE; push rBASE ; 저장 + 16바이트 정렬
     mov rdi, rBASE         ; 인자 = vtable base
     movabs rax, &__vtint_check
     call rax               ; 검사(READONLY, ID). 실패 시 내부에서 종료코드 99
     pop rBASE; pop rBASE   ; 복원
     <slot load>            ; rSLOT = vtable[k]
     jmp resume             ; 원래 호출 지점으로 복귀
"""
import sys, os, json, struct, random, subprocess, tempfile
import lief
from elfparser import ELFParser, _hex
from bitcover import run as bitcover_run

VTSEC_VA = 0x500000      # 이전된 vtable + 페이지 ID (읽기 전용)
CODE_VA  = 0x600000      # 검사 루틴 + 트램펄린 (읽기+실행)

REG = {"rax":0,"rcx":1,"rdx":2,"rbx":3,"rsp":4,"rbp":5,"rsi":6,"rdi":7,
       "r8":8,"r9":9,"r10":10,"r11":11,"r12":12,"r13":13,"r14":14,"r15":15}


# ---- 최소 x86-64 인코더 ------------------------------------------------------
def _push(i):
    return bytes([0x50 + i]) if i < 8 else bytes([0x41, 0x50 + (i - 8)])

def _pop(i):
    return bytes([0x58 + i]) if i < 8 else bytes([0x41, 0x58 + (i - 8)])

def _mov_rdi_from(i):
    # mov rdi, reg_i   (89 /r : reg=src, r/m=rdi=7)
    rex = 0x48 | (0x04 if i >= 8 else 0)   # REX.W + REX.R(src 확장 시)
    modrm = 0xC0 | ((i & 7) << 3) | 7
    return bytes([rex, 0x89, modrm])

def _movabs_rax(imm):
    return b"\x48\xb8" + struct.pack("<Q", imm)

CALL_RAX = b"\xff\xd0"


def build_check_blob(idval, runtime_dir):
    """vtint_check.c 를 ID 박아 컴파일→링크→objcopy. (blob bytes, entry_va) 반환."""
    with tempfile.TemporaryDirectory() as td:
        obj = os.path.join(td, "check.o")
        elf = os.path.join(td, "check.elf")
        binf = os.path.join(td, "check.bin")
        src = os.path.join(runtime_dir, "vtint_check.c")
        ld  = os.path.join(runtime_dir, "check.ld")
        subprocess.check_call([
            "gcc", "-DVTINT_ID=0x%016x" % idval,
            "-ffreestanding", "-fno-pic", "-fno-pie", "-fno-stack-protector",
            "-fcf-protection=none", "-fno-asynchronous-unwind-tables",
            "-fno-builtin", "-fno-tree-loop-distribute-patterns",
            "-nostdlib", "-Os", "-c", src, "-o", obj])
        subprocess.check_call(["ld", "-T", ld, "-o", elf, obj])
        subprocess.check_call(["objcopy", "-O", "binary", elf, binf])
        blob = open(binf, "rb").read()
        # __vtint_check 심볼 VA
        from elftools.elf.elffile import ELFFile
        entry = None
        with open(elf, "rb") as fh:
            ef = ELFFile(fh)
            st = ef.get_section_by_name(".symtab")
            for s in st.iter_symbols():
                if s.name == "__vtint_check":
                    entry = s["st_value"]
        assert entry is not None, "entry symbol not found"
        return blob, entry


def build_trampoline(base_reg, base_bytes, slot_bytes, check_va, resume_va, tramp_va):
    i = REG[base_reg]
    t = bytearray()
    t += base_bytes                 # rBASE = [..]
    t += _push(i)                   # save base
    t += _push(i)                   # pad (16-align)
    t += _mov_rdi_from(i)           # rdi = base
    t += _movabs_rax(check_va)      # movabs rax, &check
    t += CALL_RAX                   # call rax
    t += _pop(i)                    # discard pad
    t += _pop(i)                    # restore base
    t += slot_bytes                 # rSLOT = [base+disp]
    jmp_from = tramp_va + len(t)
    rel = resume_va - (jmp_from + 5)
    t += b"\xe9" + struct.pack("<i", rel)   # jmp resume
    return bytes(t)


def _seg(va, content, execflag):
    s = lief.ELF.Segment()
    s.type = lief.ELF.Segment.TYPE.LOAD
    f = lief.ELF.Segment.FLAGS.R
    if execflag:
        f = f | lief.ELF.Segment.FLAGS.X
    s.flags = f
    s.alignment = 0x1000
    s.virtual_address = va
    s.physical_address = va
    s.content = list(content)
    return s


class VRewriter:
    def __init__(self, in_path, cov, runtime_dir):
        self.in_path = in_path
        self.cov = cov
        self.runtime_dir = runtime_dir
        self.p = ELFParser(in_path)
        self.log = []

    def _orig_bytes(self, vaddr, size):
        for (name, a, sz, flags, data) in self.p.sections:
            if a <= vaddr < a + sz:
                off = vaddr - a
                return data[off:off + size]
        raise ValueError("vaddr 0x%x not in any section" % vaddr)

    def rewrite(self, out_path, fixed_id=None):
        idval = fixed_id if fixed_id is not None else random.getrandbits(64)

        # ---- 1. vtsec (읽기전용): ID + 이전된 vtable ----
        vtsec = bytearray()
        vtsec += struct.pack("<Q", idval)                 # 페이지 선두 ID
        newpoint = {}                                     # old addr_point -> new addr_point
        moved = []
        for v in self.cov["vtables"]:
            if not v.get("confirmed"):
                continue
            off = len(vtsec)
            new_vaddr = VTSEC_VA + off
            vtsec += self._orig_bytes(v["vaddr"], v["size"])
            delta = v["addr_point"] - v["vaddr"]          # 보통 16
            newpoint[v["addr_point"]] = new_vaddr + delta
            moved.append((v["name"], v["vaddr"], new_vaddr))
            self.log.append("[move] %s 0x%x -> 0x%x (addr_point 0x%x -> 0x%x)"
                            % (v["name"], v["vaddr"], new_vaddr,
                               v["addr_point"], new_vaddr + delta))

        # ---- 2. 검사 코드 블롭 + 트램펄린 ----
        blob, entry_va = build_check_blob(idval, self.runtime_dir)
        check_va = entry_va
        self.log.append("[check] blob %dB, __vtint_check @ 0x%x" % (len(blob), check_va))
        code = bytearray(blob)
        while len(code) % 16:
            code.append(0x90)

        window_patches = []
        for site in self.cov["vcall_sites"]:
            tramp_va = CODE_VA + len(code)
            tramp = build_trampoline(
                site["base_reg"],
                bytes.fromhex(site["base_load_bytes"]),
                bytes.fromhex(site["slot_load_bytes"]),
                check_va, site["resume_vaddr"], tramp_va)
            code += tramp
            wlen = site["window_len"]
            rel = tramp_va - (site["window_vaddr"] + 5)
            patch = b"\xe9" + struct.pack("<i", rel) + b"\x90" * (wlen - 5)
            window_patches.append((site["window_vaddr"], patch))
            self.log.append("[hook] vcall@0x%x window@0x%x -> tramp@0x%x"
                            % (site["call_vaddr"], site["window_vaddr"], tramp_va))

        # ---- 3. vtable 참조(immediate) 패치 ----
        vref_patches = []
        for r in self.cov["vref_sites"]:
            new = newpoint.get(r["imm"])
            if new is None:
                continue
            insn = bytes.fromhex(r["insn_bytes"])
            oldle = struct.pack("<I", r["imm"] & 0xffffffff)
            idx = insn.find(oldle)
            if idx < 0:
                self.log.append("[warn] imm 0x%x not found in insn@0x%x" % (r["imm"], r["vaddr"]))
                continue
            vref_patches.append((r["vaddr"] + idx, struct.pack("<I", new & 0xffffffff)))
            self.log.append("[ref] @0x%x  0x%x -> 0x%x" % (r["vaddr"], r["imm"], new))

        # ---- 4. LIEF 로 세그먼트 추가 + 패치 ----
        b = lief.parse(self.in_path)
        b.add(_seg(VTSEC_VA, bytes(vtsec), execflag=False))
        b.add(_seg(CODE_VA, bytes(code), execflag=True))
        for (va, by) in window_patches + vref_patches:
            b.patch_address(va, list(by))
        b.write(out_path)
        os.chmod(out_path, 0o755)

        meta = {
            "id": "0x%016x" % idval,
            "vtsec_va": "0x%x" % VTSEC_VA,
            "code_va": "0x%x" % CODE_VA,
            "check_va": "0x%x" % check_va,
            "moved_vtables": [{"name": n, "old": "0x%x" % o, "new": "0x%x" % nv} for (n, o, nv) in moved],
            "hooked_vcalls": len(self.cov["vcall_sites"]),
            "patched_refs": len(vref_patches),
        }
        return meta


def run(in_path, out_path, runtime_dir, fixed_id=None):
    cov = bitcover_run(in_path)
    rw = VRewriter(in_path, cov, runtime_dir)
    meta = rw.rewrite(out_path, fixed_id=fixed_id)
    return meta, rw.log


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("usage: vrewriter.py <in_elf> <out_elf> [runtime_dir]", file=sys.stderr); sys.exit(2)
    rtd = sys.argv[3] if len(sys.argv) > 3 else os.path.join(os.path.dirname(__file__), "..", "runtime")
    meta, log = run(sys.argv[1], sys.argv[2], os.path.abspath(rtd))
    for l in log:
        print(l, file=sys.stderr)
    print(json.dumps(meta, indent=2, ensure_ascii=False))
    print("\n[VRewriter] 보호 바이너리 생성: %s" % sys.argv[2], file=sys.stderr)
