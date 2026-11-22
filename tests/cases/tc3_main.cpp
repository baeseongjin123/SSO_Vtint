// TC3 취약 프로그램 — 다단계 상속(A→B→C). A* 로 가상 호출하지만 실제로는 C 의 vtable 사용.
// 대상 가상 함수는 slot 0.
//   normal : DERIVED RUN, exit 0
//   inject : (보호 전) HIJACKED, exit 66
//   rodata : (보호 전) HIJACKED, exit 66
#include "tc3.h"
#include <cstdint>
#include <cstdlib>
#include <cstring>

static void (*const g_rodata_fptrs[1])() = { hijacked };   // .rodata, slot 0 = 공격자

struct Victim {
    char buf[16];
    alignas(8) unsigned char obj[sizeof(C)];
};

static void unsafe_copy(void* dst, const void* src, size_t n) {
    volatile unsigned char* d = (volatile unsigned char*)dst;
    const unsigned char* s = (const unsigned char*)src;
    for (size_t i = 0; i < n; i++) d[i] = s[i];
}

int main(int argc, char** argv) {
    const char* mode = (argc > 1) ? argv[1] : "normal";

    Victim v;
    A* a = make_c(v.obj);

    unsigned char payload[24];
    std::memset(payload, 'A', 16);
    uint64_t newvfptr = 0;

    if (std::strcmp(mode, "normal") == 0) {
        const char* in = "hi";
        unsafe_copy(v.buf, in, std::strlen(in) + 1);
    } else if (std::strcmp(mode, "inject") == 0) {
        void** fake = (void**)std::malloc(sizeof(void*) * 2);
        fake[0] = (void*)&hijacked;
        std::printf("[leak] fake vtable @ %p (heap, writable)\n", (void*)fake);
        newvfptr = (uint64_t)fake;
        std::memcpy(payload + 16, &newvfptr, 8);
        unsafe_copy(v.buf, payload, 24);
    } else if (std::strcmp(mode, "rodata") == 0) {
        newvfptr = (uint64_t)(void*)g_rodata_fptrs;
        std::printf("[leak] rodata fptr array @ %p (read-only)\n", (void*)g_rodata_fptrs);
        std::memcpy(payload + 16, &newvfptr, 8);
        unsafe_copy(v.buf, payload, 24);
    } else {
        std::fprintf(stderr, "unknown mode: %s\n", mode);
        return 2;
    }

    std::fflush(stdout);
    a->act();   // 가상 호출 (slot 0): C::act 로 디스패치
    return 0;
}
