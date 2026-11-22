// C. 검사 루틴(runtime/vtint_check.c) 단위 테스트 하네스
//
// VRewriter 가 주입하는 __vtint_check() 를 일반 프로그램에 그대로 링크해서
// 여러 종류의 주소를 직접 넘겨 본다. 테스트가 VTINT_ID 를 같은 값으로 맞춰 컴파일한다.
//
// 사용법: check_harness <case>
// 출력:   ADDR=0x<넘긴 주소>   (검사 전, stdout flush)
//         통과하면 PASS 출력 후 종료 0
//         실패하면 검사 루틴이 stderr 에 VTINT DETECTED ... 출력 후 종료 99
#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#ifndef VTINT_ID
#define VTINT_ID 0x1122334455667788UL
#endif
#define PAGE 4096UL

void __vtint_check(unsigned long vtbl);  // runtime/vtint_check.c

static void target(void) { puts("TARGET"); }
static void (*const g_rodata[4])(void) = {target, target, target, target};  // .rodata
static void* g_data[4] = {(void*)target};                                   // .data

static int check(const void* p) {
    printf("ADDR=%#lx\n", (unsigned long)(uintptr_t)p);
    fflush(stdout);
    __vtint_check((unsigned long)(uintptr_t)p);
    puts("PASS");
    fflush(stdout);
    return 0;
}

// 첫 8바이트에 id 를 쓰고 prot 권한으로 바꾼 n 페이지 매핑
static char* id_pages(size_t n, unsigned long id, int prot) {
    char* p = mmap(NULL, n * PAGE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) { perror("mmap"); exit(2); }
    memcpy(p, &id, 8);
    memset(p + 8, 0x41, 64);  // 가짜 vtable 내용
    if (mprotect(p, n * PAGE, prot) != 0) { perror("mprotect"); exit(2); }
    return p;
}

int main(int argc, char** argv) {
    if (argc < 2) { fprintf(stderr, "usage: %s <case>\n", argv[0]); return 2; }
    const char* c = argv[1];

    if (!strcmp(c, "ro_id"))          return check(id_pages(1, VTINT_ID, PROT_READ) + 8 + 16);
    if (!strcmp(c, "ro_id_page_end")) return check(id_pages(1, VTINT_ID, PROT_READ) + PAGE - 8);
    if (!strcmp(c, "heap")) {
        void** fake = malloc(4 * sizeof(void*));
        fake[0] = (void*)target;
        return check(fake);
    }
    if (!strcmp(c, "stack")) {
        void* local[4] = {(void*)target};
        return check(local);
    }
    if (!strcmp(c, "data"))           return check(g_data);
    if (!strcmp(c, "rodata"))         return check((const void*)g_rodata);
    if (!strcmp(c, "code"))           return check((const void*)&target);
    if (!strcmp(c, "null"))           return check(NULL);
    if (!strcmp(c, "unmapped")) {
        void* p = mmap(NULL, PAGE, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        munmap(p, PAGE);
        return check(p);
    }
    if (!strcmp(c, "rw_with_id"))     return check(id_pages(1, VTINT_ID, PROT_READ | PROT_WRITE) + 24);
    if (!strcmp(c, "ro_wrong_id"))    return check(id_pages(1, VTINT_ID ^ 1, PROT_READ) + 24);
    if (!strcmp(c, "rx_with_id"))     return check(id_pages(1, VTINT_ID, PROT_READ | PROT_EXEC) + 24);
    if (!strcmp(c, "second_page")) {
        // 2페이지 읽기 전용 영역, ID 는 첫 페이지에만 (vtsec 이 4KB 를 넘을 때의 상황)
        char* p = id_pages(2, VTINT_ID, PROT_READ);
        return check(p + PAGE + 16);
    }
    if (!strcmp(c, "big_maps")) {
        // 정상 vtable 페이지를 먼저 만들고, 그 아래에 매핑 수천 개를 만들어
        // /proc/self/maps 를 64KB(검사 루틴 버퍼) 넘게 키운다.
        char* vt = id_pages(1, VTINT_ID, PROT_READ);
        for (int i = 0; i < 3000; i++) {
            int prot = (i & 1) ? PROT_READ : PROT_READ | PROT_WRITE;  // 인접 매핑 병합 방지
            if (mmap(NULL, PAGE, prot, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0) == MAP_FAILED) break;
        }
        return check(vt + 24);
    }
    fprintf(stderr, "unknown case: %s\n", c);
    return 2;
}
