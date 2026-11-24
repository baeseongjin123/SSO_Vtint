// 13주차 확장 검증 프로그램.  사용법: w13 <mode>
//
// N_*  정상 입력   : 보호 전·후 출력이 같고 VTINT DETECTED 가 없어야 한다 (오탐 검사)
// K_*  계측 범위   : 객체의 vptr 을 "진짜 vtable 을 그대로 복사한 사본"으로 바꾼 뒤 호출한다.
//                    사본 내용이 원본과 같으므로 보호 전에는 정상 출력(탈취 없음, 종료 0).
//                    보호 후에는 그 호출 지점이 검사를 거친다면 반드시 탐지(99)돼야 한다.
//                    → 탐지가 안 나오면 "그 형태의 가상 호출은 계측되지 않았다"는 뜻.
//                    K_heap_* : 사본이 힙(rw-p)      → READONLY 로 탐지돼야 함
//                    K_ro_*   : 사본이 읽기 전용 페이지(r--p, ID 없음) → ID 로 탐지돼야 함
// L_*  원논문 한계 : vptr 을 다른 "진짜" vtable 위치로 바꿈. 원논문도 막지 못한다고 밝힌 경우.
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <pthread.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>
#include "w13.h"

// ---- 계측 범위 검사용: vtable 사본 만들기 --------------------------------------
// obj 가 가리키는 (부분)객체의 vptr 을 읽어 [vptr-pre, vptr+8*n) 을 복사하고 vptr 을 사본으로 바꾼다.
static void retarget(void* obj, int pre, int n, bool readonly) {
    char* vptr = *(char**)obj;
    size_t len = pre + 8 * n;
    char* mem;
    if (readonly) {
        mem = (char*)mmap(nullptr, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        std::memcpy(mem + 64, vptr - pre, len);          // 페이지 선두(ID 자리)는 0 으로 둠
        mprotect(mem, 4096, PROT_READ);
        *(char**)obj = mem + 64 + pre;
    } else {
        mem = (char*)std::malloc(len);
        std::memcpy(mem, vptr - pre, len);
        *(char**)obj = mem + pre;
    }
}

// ---- 자원 관련 정상 사례 ------------------------------------------------------
static void* thread_body(void* arg) {
    Base* p = (Base*)arg;
    for (int i = 0; i < 200; i++) p->f0();
    return nullptr;
}

static int run_threads(size_t stack) {
    Base* p = make_derived();
    pthread_t t[4];
    pthread_attr_t at;
    pthread_attr_init(&at);
    if (stack) pthread_attr_setstacksize(&at, stack);
    for (auto& x : t) pthread_create(&x, &at, thread_body, p);
    for (auto& x : t) pthread_join(x, nullptr);
    std::puts("THREADS DONE");
    return 0;
}

#define IS(s) (std::strcmp(m, s) == 0)

int main(int argc, char** argv) {
    const char* m = argc > 1 ? argv[1] : "N_slot1";
    long k = argc;   // 상수 전파 방지용

    // ------------------------------------------------------------- N: 정상
    if (IS("N_slot1"))      { Base* p = make_derived(); p->f1(); }
    else if (IS("N_slot3")) { Base* p = make_derived(); p->f3(); }
    else if (IS("N_wide20")){ Wide* w = make_wide(); w->w20(); }
    else if (IS("N_vdtor")) { Base* p = make_derived(); delete p; }
    else if (IS("N_args"))  { Base* p = make_derived();
                              long r = p->sum6(k, k * 10, k * 100, k * 1000, k * 10000);
                              std::printf("SUM6 %ld\n", r); }
    else if (IS("N_m3_pb")) { PB* b = make_m3(); b->pb(); }
    else if (IS("N_m3_pc")) { PC* c = make_m3(); c->pc(); }
    else if (IS("N_vd_vl")) { VL* l = make_vd(); l->vl(); }
    else if (IS("N_vd_vr")) { VR* r = make_vd(); r->vr(); }
    else if (IS("N_vd_vb")) { VB* b = make_vd(); b->vb(); }
    else if (IS("N_abstract")) { Shape* s = make_square(); std::printf("AREA %d\n", s->area()); }
    else if (IS("N_static")) { Base* p = &g_static_derived; p->f0(); }
    else if (IS("N_lib_derived")) { std::exception* e = make_myerr(); std::puts(e->what()); }
    else if (IS("N_lib_object")) {
        try { throw std::runtime_error("LIB WHAT"); }
        catch (std::exception& e) { std::puts(e.what()); }
    }
    else if (IS("N_threads"))     return run_threads(0);
    else if (IS("N_small_stack")) return run_threads(64 * 1024);
    else if (IS("N_fd_exhausted")) {
        Base* p = make_derived();
        struct rlimit rl = {32, 32};
        setrlimit(RLIMIT_NOFILE, &rl);
        while (open("/dev/null", O_RDONLY) >= 0) {}      // 파일 디스크립터를 모두 씀
        p->f0();
    }
    else if (IS("N_many_maps")) {
        Base* p = make_derived();
        for (int i = 0; i < 3000; i++)
            mmap(nullptr, 4096, (i & 1) ? PROT_READ : PROT_READ | PROT_WRITE,
                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        p->f0();
    }
    else if (IS("N_fork")) {
        Base* p = make_derived();
        std::fflush(stdout);
        pid_t c = fork();
        if (c == 0) { p->f1(); std::fflush(stdout); _exit(0); }
        int st = 0; waitpid(c, &st, 0);
        if (!WIFEXITED(st) || WEXITSTATUS(st) != 0) { std::printf("CHILD FAILED %d\n", st); return 3; }
        p->f0();
    }
    // ------------------------------------------------------------- K: 계측 범위
    else if (IS("K_heap_slot0")) { Base* p = make_derived(); retarget(p, 16, 8, false); p->f0(); }
    else if (IS("K_heap_slot1")) { Base* p = make_derived(); retarget(p, 16, 8, false); p->f1(); }
    else if (IS("K_heap_slot3")) { Base* p = make_derived(); retarget(p, 16, 8, false); p->f3(); }
    else if (IS("K_heap_wide20")){ Wide* w = make_wide(); retarget(w, 16, 23, false); w->w20(); }
    else if (IS("K_heap_args"))  { Base* p = make_derived(); retarget(p, 16, 8, false);
                                   std::printf("SUM6 %ld\n", p->sum6(k, k * 10, k * 100, k * 1000, k * 10000)); }
    else if (IS("K_heap_vdtor")) { Base* p = make_derived(); retarget(p, 16, 8, false); delete p; }
    else if (IS("K_heap_m3_pb")) { PB* b = make_m3(); retarget(b, 16, 3, false); b->pb(); }
    else if (IS("K_heap_m3_pc")) { PC* c = make_m3(); retarget(c, 16, 3, false); c->pc(); }
    else if (IS("K_heap_vd_vr")) { VR* r = make_vd(); retarget(r, 24, 3, false); r->vr(); }
    else if (IS("K_ro_slot0"))   { Base* p = make_derived(); retarget(p, 16, 8, true); p->f0(); }
    else if (IS("K_ro_slot1"))   { Base* p = make_derived(); retarget(p, 16, 8, true); p->f1(); }
    // ------------------------------------------------------------- L: 원논문 한계
    else if (IS("L_reuse")) {      // Derived 객체가 Base 의 진짜 vtable 을 쓰게 함
        Base* d = make_derived(); Base* b = make_base();
        *(void**)d = *(void**)b;
        d->f0();                   // 보호 전·후 모두 "BASE F0" 예상
    }
    else if (IS("L_mid")) {        // 같은 vtable 안에서 한 칸 밀린 위치
        Base* d = make_derived();
        *(char**)d += 8;
        d->f0();                   // 보호 전·후 모두 "DERIVED F1" 예상
    }
    else { std::fprintf(stderr, "unknown mode: %s\n", m); return 2; }
    return 0;
}
