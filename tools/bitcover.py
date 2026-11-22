#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
BitCover  (논문의 BitCover 를 ELF/x86-64 에 대응)

역할: ELFParser 가 준 후보 vtable 을 바탕으로 바이너리를 디스어셈블(capstone)하여
  (1) 가상 호출 지점(virtual call site) 을 찾고,
  (2) 각 호출 직전의 'vtable base 포인터가 살아있는' 계측 윈도우를 확정하며,
  (3) 코드 안의 vtable 주소 참조(생성자의 vfptr 대입) 를 찾아 후보를 '진짜 vtable' 로 확정한다.

가상 호출 코드 패턴 (g++ -O0, Itanium ABI):
    mov rBASE, [rTHIS]        ; 객체에서 vfptr 로드  → rBASE = vtable base   (base load)
    mov rSLOT, [rBASE + k*8]  ; 슬롯에서 함수포인터 로드                       (slot load)
    ...
    call rSLOT               ; 간접 호출 = 가상 디스패치

계측 윈도우 = [base load .. slot load] (연속). 이 구간을 트램펄린으로 detour 하면
base load 직후 rBASE(=vtable) 로 검사 루틴을 호출할 수 있다.
"""
import sys, json, struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_REG as CS_OP_REG, X86_OP_MEM as CS_OP_MEM, X86_OP_IMM as CS_OP_IMM
from elfparser import ELFParser, _hex


class BitCover:
    def __init__(self, parser: ELFParser, parse_result: dict):
        self.p = parser
        self.pr = parse_result
        self.md = Cs(CS_ARCH_X86, CS_MODE_64)
        self.md.detail = True
        self.vtable_addr_points = {v["addr_point"]: v for v in parse_result["candidate_vtables"]}

    def _exec_sections(self):
        out = []
        for (name, addr, size, flags, data) in self.p.sections:
            if flags & 0x4:  # SHF_EXECINSTR
                out.append((name, addr, data))
        return out

    def analyze(self):
        vcall_sites = []
        vref_sites = []
        for (name, base, data) in self._exec_sections():
            insns = list(self.md.disasm(data, base))
            # 주소 → 인덱스
            for idx, ins in enumerate(insns):
                # ---- (3) vtable 주소 참조 (immediate) ----
                for op in ins.operands:
                    if op.type == CS_OP_IMM and op.imm in self.vtable_addr_points:
                        vt = self.vtable_addr_points[op.imm]
                        vref_sites.append({
                            "vaddr": ins.address,
                            "text": "%s %s" % (ins.mnemonic, ins.op_str),
                            "insn_bytes": ins.bytes.hex(),
                            "imm": op.imm,
                            "imm_size": op.size if op.size in (4, 8) else 4,
                            "target_vtable": vt["name"],
                            "target_addr_point": op.imm,
                        })
                # ---- (1)(2) 가상 호출 지점 ----
                if ins.mnemonic == "call" and len(ins.operands) == 1 and \
                        ins.operands[0].type == CS_OP_REG:
                    site = self._match_vcall(insns, idx)
                    if site:
                        vcall_sites.append(site)
        return {"vcall_sites": vcall_sites, "vref_sites": vref_sites}

    def _match_vcall(self, insns, call_idx):
        """call rSLOT 에서 역추적하여 base load / slot load 윈도우 확정."""
        call = insns[call_idx]
        slot_reg = call.operands[0].reg
        # 역방향으로 slot_reg 를 메모리 로드로 정의하는 slot load 찾기
        for k in range(call_idx - 1, max(-1, call_idx - 10), -1):
            ins = insns[k]
            if ins.mnemonic != "mov" or len(ins.operands) != 2:
                # slot_reg 가 다른 방식으로 재정의되면 중단
                if self._writes_reg(ins, slot_reg):
                    return None
                continue
            dst, src = ins.operands
            if dst.type == CS_OP_REG and dst.reg == slot_reg and src.type == CS_OP_MEM:
                # slot load 발견. 메모리 base 레지스터 = vtable base.
                base_reg = src.mem.base
                if base_reg == 0:
                    return None
                slot_load = ins
                # 바로 앞 명령이 base load (mov base_reg, [reg]) 인지 확인
                if k - 1 < 0:
                    return None
                prev = insns[k - 1]
                if prev.mnemonic == "mov" and len(prev.operands) == 2:
                    pdst, psrc = prev.operands
                    if pdst.type == CS_OP_REG and pdst.reg == base_reg and psrc.type == CS_OP_MEM:
                        base_load = prev
                        win_start = base_load.address
                        win_end = slot_load.address + slot_load.size
                        win_len = win_end - win_start
                        if win_len < 5:
                            return None
                        win_bytes = bytes(base_load.bytes) + bytes(slot_load.bytes)
                        return {
                            "call_vaddr": call.address,
                            "call_text": "%s %s" % (call.mnemonic, call.op_str),
                            "base_reg": base_load.reg_name(base_reg),
                            "slot_reg": call.reg_name(slot_reg),
                            "window_vaddr": win_start,
                            "window_len": win_len,
                            "window_bytes": win_bytes.hex(),
                            "base_load_bytes": bytes(base_load.bytes).hex(),
                            "slot_load_bytes": bytes(slot_load.bytes).hex(),
                            "resume_vaddr": win_end,
                            "base_load": "%s %s" % (base_load.mnemonic, base_load.op_str),
                            "slot_load": "%s %s" % (slot_load.mnemonic, slot_load.op_str),
                        }
            if dst.type == CS_OP_REG and dst.reg == slot_reg:
                return None  # slot_reg 가 메모리 로드가 아닌 다른 것으로 정의됨
        return None

    @staticmethod
    def _writes_reg(ins, reg):
        try:
            _, regs_write = ins.regs_access()
            return reg in regs_write
        except Exception:
            return False


def run(path):
    p = ELFParser(path)
    pr = p.result()
    bc = BitCover(p, pr)
    cov = bc.analyze()
    # 참조가 있는 vtable 을 '확정' 으로 표기
    referenced = {v["target_addr_point"] for v in cov["vref_sites"]}
    confirmed = []
    for v in pr["candidate_vtables"]:
        v = dict(v)
        v["confirmed"] = v["addr_point"] in referenced
        confirmed.append(v)
    return {
        "path": path,
        "vtables": confirmed,
        "vcall_sites": cov["vcall_sites"],
        "vref_sites": cov["vref_sites"],
    }


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("usage: bitcover.py <elf>", file=sys.stderr); sys.exit(2)
    r = run(sys.argv[1])
    print(json.dumps(_hex(r), indent=2, ensure_ascii=False))
    print("\n[BitCover] 확정 vtable %d, 가상호출 %d, vtable 참조 %d" % (
        sum(1 for v in r["vtables"] if v["confirmed"]),
        len(r["vcall_sites"]), len(r["vref_sites"])), file=sys.stderr)
