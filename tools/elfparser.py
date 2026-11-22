#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ELFParser  (논문의 PEParser 를 ELF 에 대응)

역할: 컴파일된 ELF(exe)를 파싱하여 '후보 vtable' 과 읽기 전용 섹션 정보를 뽑는다.

논문(III-C)의 vtable 식별 원리:
  - vtable 주소는 생성자에서 쓰이고, 엔트리는 모두 가상 함수 포인터다.
  - 따라서 "코드 섹션을 가리키는 포인터들의 배열" 이 곧 후보 vtable 이다.
ELF(-no-pie)에서는 포인터가 절대주소로 섹션 바이트에 박혀 있으므로,
읽기 전용 섹션을 8바이트 단위로 훑어 '.text 를 가리키는 포인터 배열' 을 찾는다.
(심볼이 남아 있으면 _ZTV* 이름을 붙여 보고에 활용 — 식별 자체는 스캔으로 수행)

Itanium C++ ABI vtable 레이아웃:
   [ offset-to-top(8) ][ typeinfo ptr(8) ][ fnptr0 ][ fnptr1 ] ...
   vfptr(객체에 저장되는 값) = 테이블시작 + 16  (= address point)
"""
import sys, json, struct
from elftools.elf.elffile import ELFFile


def _u64(b, off):
    return struct.unpack_from("<Q", b, off)[0]


class ELFParser:
    def __init__(self, path):
        self.path = path
        self.f = open(path, "rb")
        self.elf = ELFFile(self.f)
        self.is_pie = (self.elf.header["e_type"] == "ET_DYN")
        self.sections = []      # [(name, addr, size, flags, data)]
        self.text_ranges = []   # [(start,end)] 실행 섹션
        self.ro_ranges = []     # [(name,start,end)] 읽기전용(비실행) 섹션
        self._load_sections()
        self.symbols = self._load_symbols()

    def _load_sections(self):
        for s in self.elf.iter_sections():
            h = s.header
            if h["sh_type"] == "SHT_NOBITS":
                continue
            addr = h["sh_addr"]
            if addr == 0:
                continue
            flags = h["sh_flags"]
            data = s.data()
            self.sections.append((s.name, addr, h["sh_size"], flags, data))
            SHF_WRITE, SHF_EXEC, SHF_ALLOC = 0x1, 0x4, 0x2
            if not (flags & SHF_ALLOC):
                continue
            if flags & SHF_EXEC:
                self.text_ranges.append((addr, addr + h["sh_size"]))
            elif not (flags & SHF_WRITE):
                # 읽기 전용 비실행 (.rodata 등)
                self.ro_ranges.append((s.name, addr, addr + h["sh_size"]))
            # .data.rel.ro 는 WRITE 플래그가 있으나 RELRO 로 런타임 읽기전용.
            # vtable(-no-pie)은 .rodata 에 오므로 여기선 .rodata 중심으로 스캔.

    def _load_symbols(self):
        syms = {}
        for secname in (".symtab", ".dynsym"):
            sec = self.elf.get_section_by_name(secname)
            if not sec:
                continue
            for sym in sec.iter_symbols():
                v = sym["st_value"]
                if v and sym.name:
                    syms.setdefault(v, sym.name)
        return syms

    def in_text(self, addr):
        return any(s <= addr < e for (s, e) in self.text_ranges)

    def _section_of(self, addr):
        for (name, a, size, flags, data) in self.sections:
            if a <= addr < a + size:
                return name, a, data
        return None, None, None

    def find_candidate_vtables(self):
        """읽기 전용 섹션에서 '코드 포인터 배열' = 후보 vtable 탐색."""
        cands = []
        for (name, start, end) in self.ro_ranges:
            _, base, data = self._section_of(start)
            secbytes = data
            secbase = base
            n = len(secbytes)
            i = 0
            while i + 8 <= n:
                # Itanium vtable 패턴 시도: [0][typeinfo][fnptr+...]
                off_top = _u64(secbytes, i)
                if off_top != 0:
                    i += 8
                    continue
                if i + 16 > n:
                    break
                ti = _u64(secbytes, i + 8)   # typeinfo 포인터(코드가 아닌 데이터 가리킴)
                # 세 번째 슬롯부터 .text 포인터가 연속되면 vtable
                j = i + 16
                entries = []
                while j + 8 <= n:
                    val = _u64(secbytes, j)
                    if self.in_text(val):
                        entries.append(val)
                        j += 8
                    else:
                        break
                if entries and not self.in_text(ti):
                    vaddr = secbase + i
                    addr_point = vaddr + 16
                    cands.append({
                        "name": self.symbols.get(vaddr, "vtable@0x%x" % vaddr),
                        "vaddr": vaddr,
                        "addr_point": addr_point,
                        "size": (j - i),
                        "typeinfo": ti,
                        "entries": entries,
                        "section": name,
                    })
                    i = j  # 이 테이블 건너뜀
                else:
                    i += 8
        return cands

    def result(self):
        return {
            "path": self.path,
            "arch": self.elf.get_machine_arch(),
            "pie": self.is_pie,
            "entry": self.elf.header["e_entry"],
            "text_ranges": [[s, e] for (s, e) in self.text_ranges],
            "ro_sections": [{"name": n, "start": s, "end": e} for (n, s, e) in self.ro_ranges],
            "candidate_vtables": self.find_candidate_vtables(),
        }


def _hex(o):
    if isinstance(o, dict):
        return {k: _hex(v) for k, v in o.items()}
    if isinstance(o, list):
        return [_hex(v) for v in o]
    if isinstance(o, int) and o > 0xffff:
        return "0x%x" % o
    return o


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("usage: elfparser.py <elf>", file=sys.stderr); sys.exit(2)
    p = ELFParser(sys.argv[1])
    r = p.result()
    print(json.dumps(_hex(r), indent=2, ensure_ascii=False))
    print("\n[ELFParser] 후보 vtable %d 개 식별" % len(r["candidate_vtables"]), file=sys.stderr)
