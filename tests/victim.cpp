// 취약 프로그램 (보호 전 입력 바이너리의 소스).
//
// 메모리 레이아웃:  Victim { char buf[16]; <vfptr>objstore... }
// buf 를 16바이트 넘겨 쓰면 바로 뒤 objstore(=Derived 객체 vfptr)를 덮는다.
// "정보 유출"을 가정하여 가짜 vtable/rodata 주소는 프로그램이 직접 알려준다.
//
// 모드(argv[1]):
//   normal : 오버플로 없음          → DERIVED RUN, exit 0
//   inject : 힙 가짜 vtable 로 덮음  → (보호 전) HIJACKED, exit 66
//   rodata : .rodata 포인터배열로 덮음→ (보호 전) HIJACKED, exit 66
#include "common.h"
#include <cstdint>
#include <cstring>

// .rodata(읽기 전용)에 놓이는 const 함수 포인터 배열.
// vtable 이 아니지만 slot0 이 공격자 함수를 가리킨다 → vtable reuse(경계) 표적.
static void (*const g_rodata_fptrs[1])() = { hijacked };

struct Victim {
    char buf[16];
    alignas(8) unsigned char objstore[sizeof(Derived)];
};

// fortify/최적화에 지워지지 않도록 volatile 바이트 복사로 '진짜' 오버플로를 낸다.
static void unsafe_copy(void* dst, const void* src, size_t n) {
    volatile unsigned char* d = (volatile unsigned char*)dst;
    const unsigned char* s = (const unsigned char*)src;
    for (size_t i = 0; i < n; i++) d[i] = s[i];
}

int main(int argc, char** argv) {
    const char* mode = (argc > 1) ? argv[1] : "normal";

    Victim v;
    Base* b = make_derived(v.objstore);   // vfptr = &v.objstore[0] (offset 16)

    unsigned char payload[24];
    std::memset(payload, 'A', 16);        // buf 채움
    uint64_t newvfptr = 0;

    if (std::strcmp(mode, "normal") == 0) {
        const char* in = "hello";
        unsafe_copy(v.buf, in, std::strlen(in) + 1);   // 오버플로 없음
    } else if (std::strcmp(mode, "inject") == 0) {
        void** fake = (void**)std::malloc(sizeof(void*) * 2);
        fake[0] = (void*)&hijacked;                    // 가짜 vtable slot0
        std::printf("[leak] fake vtable @ %p (heap, writable)\n", (void*)fake);
        newvfptr = (uint64_t)fake;
        std::memcpy(payload + 16, &newvfptr, 8);
        unsafe_copy(v.buf, payload, 24);               // ← 의도된 오버플로
    } else if (std::strcmp(mode, "rodata") == 0) {
        newvfptr = (uint64_t)(void*)g_rodata_fptrs;    // .rodata 재사용
        std::printf("[leak] rodata fptr array @ %p (read-only)\n", (void*)g_rodata_fptrs);
        std::memcpy(payload + 16, &newvfptr, 8);
        unsafe_copy(v.buf, payload, 24);               // ← 의도된 오버플로
    } else {
        std::fprintf(stderr, "unknown mode: %s\n", mode);
        return 2;
    }

    std::fflush(stdout);
    b->run();     // 가상 호출: *(vfptr) → vtable[0] → 대상 함수
    return 0;
}
