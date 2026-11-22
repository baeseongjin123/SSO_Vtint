// TC1 취약 프로그램.
//   메모리 배치: Victim { char buf[16]; <Rect 객체(맨 앞 8B = vfptr)> }
//   buf 를 16바이트 넘겨 쓰면 바로 뒤 객체의 vfptr(slot 0 대상)을 덮는다.
//
//   normal : 오버플로 없음              → DERIVED RUN, exit 0
//   inject : 힙 가짜 vtable 로 덮음      → (보호 전) HIJACKED, exit 66
//   rodata : .rodata 포인터배열로 덮음   → (보호 전) HIJACKED, exit 66
#include "tc1.h"
#include <cstdint>
#include <cstdlib>
#include <cstring>

// .rodata(읽기 전용)의 const 함수 포인터 배열. slot 0 이 공격자 함수를 가리킨다.
static void (*const g_rodata_fptrs[1])() = { hijacked };

struct Victim {
    char buf[16];
    alignas(8) unsigned char obj[sizeof(Rect)];
};

// 최적화/fortify 에 지워지지 않도록 volatile 바이트 복사로 '진짜' 오버플로를 낸다.
static void unsafe_copy(void* dst, const void* src, size_t n) {
    volatile unsigned char* d = (volatile unsigned char*)dst;
    const unsigned char* s = (const unsigned char*)src;
    for (size_t i = 0; i < n; i++) d[i] = s[i];
}

int main(int argc, char** argv) {
    const char* mode = (argc > 1) ? argv[1] : "normal";

    Victim v;
    Shape* sh = make_rect(v.obj);          // vfptr = &v.obj[0]

    unsigned char payload[24];
    std::memset(payload, 'A', 16);         // buf 채움
    uint64_t newvfptr = 0;

    if (std::strcmp(mode, "normal") == 0) {
        const char* in = "hi";
        unsafe_copy(v.buf, in, std::strlen(in) + 1);          // 오버플로 없음
    } else if (std::strcmp(mode, "inject") == 0) {
        void** fake = (void**)std::malloc(sizeof(void*) * 2);
        fake[0] = (void*)&hijacked;                           // slot 0
        std::printf("[leak] fake vtable @ %p (heap, writable)\n", (void*)fake);
        newvfptr = (uint64_t)fake;
        std::memcpy(payload + 16, &newvfptr, 8);
        unsafe_copy(v.buf, payload, 24);                      // ← 의도된 오버플로
    } else if (std::strcmp(mode, "rodata") == 0) {
        newvfptr = (uint64_t)(void*)g_rodata_fptrs;
        std::printf("[leak] rodata fptr array @ %p (read-only)\n", (void*)g_rodata_fptrs);
        std::memcpy(payload + 16, &newvfptr, 8);
        unsafe_copy(v.buf, payload, 24);                      // ← 의도된 오버플로
    } else {
        std::fprintf(stderr, "unknown mode: %s\n", mode);
        return 2;
    }

    std::fflush(stdout);
    sh->draw();   // 가상 호출 (slot 0): *(vfptr) → vtable[0] → 대상 함수
    return 0;
}
