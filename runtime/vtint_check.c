// VTint 런타임 검사 루틴 (freestanding, libc 비의존 · raw syscall).
//
// VRewriter 가 이 .text 바이트를 바이너리 안의 새 실행 세그먼트에 주입한다.
// 각 가상 호출 직전 트램펄린이 vtable base 포인터를 rdi 로 넘겨 호출한다:
//      __vtint_check(vtbl)
//
// 두 가지 검사(논문 III-E, 3팀 포인트):
//   (1) READONLY : /proc/self/maps 에서 vtbl 이 속한 매핑이 쓰기 가능하면 탈락
//                  → vtable injection(힙 가짜 테이블) 차단
//   (2) ID       : vtbl 의 페이지 선두 8바이트가 주입 ID 와 다르면 탈락
//                  → 읽기 전용이지만 vtable 이 아닌 .rodata 재사용 차단
// 통과하면 그대로 복귀하여 원래 가상 호출을 수행한다.
//
// 빌드: gcc -DVTINT_ID=0x... -ffreestanding -fno-pic -fno-stack-protector \
//           -fcf-protection=none -fno-asynchronous-unwind-tables \
//           -fno-builtin -nostdlib -Os ...
#ifndef VTINT_ID
#define VTINT_ID 0x1122334455667788UL
#endif

typedef unsigned long u64;
typedef long i64;

// ---- raw syscalls (x86-64) -------------------------------------------------
static inline i64 sys3(i64 n, i64 a, i64 b, i64 c) {
    i64 ret;
    __asm__ volatile("syscall"
                     : "=a"(ret)
                     : "a"(n), "D"(a), "S"(b), "d"(c)
                     : "rcx", "r11", "memory");
    return ret;
}
#define SYS_read   0
#define SYS_write  1
#define SYS_open   2
#define SYS_close  3
#define SYS_exit   60

static inline i64 k_open(const char* p, i64 flags) { return sys3(SYS_open,(i64)p,flags,0); }
static inline i64 k_read(i64 fd, void* b, i64 n)   { return sys3(SYS_read,fd,(i64)b,n); }
static inline i64 k_write(i64 fd, const void* b, i64 n){ return sys3(SYS_write,fd,(i64)b,n); }
static inline void k_exit(i64 c) { sys3(SYS_exit,c,0,0); __builtin_unreachable(); }

// ---- 작은 유틸 --------------------------------------------------------------
static i64 slen(const char* s){ i64 n=0; while(s[n]) n++; return n; }
static void emit(const char* s){ k_write(2, s, slen(s)); }

// u64 -> "0x...." (16자리) ; buf 는 최소 19바이트
static void hex64(u64 v, char* buf){
    const char* d="0123456789abcdef";
    buf[0]='0'; buf[1]='x';
    for(int i=0;i<16;i++) buf[2+i]=d[(v>>((15-i)*4))&0xf];
    buf[18]=0;
}

// 한 줄에서 공백 전까지의 16진수 start/end 와 perms 를 파싱.
// 형식 예: "00400000-00401000 r--p 00000000 ..."
// 성공 시 1, start/end/perms 채움.
static int parse_line(const char* p, const char* end, u64* s, u64* e, char* perms){
    u64 v=0; const char* q=p;
    while(q<end && *q!='-'){ char c=*q; int h;
        if(c>='0'&&c<='9') h=c-'0';
        else if(c>='a'&&c<='f') h=c-'a'+10;
        else return 0;
        v=(v<<4)|h; q++; }
    if(q>=end||*q!='-') return 0; *s=v; q++;
    v=0;
    while(q<end && *q!=' '){ char c=*q; int h;
        if(c>='0'&&c<='9') h=c-'0';
        else if(c>='a'&&c<='f') h=c-'a'+10;
        else return 0;
        v=(v<<4)|h; q++; }
    if(q>=end||*q!=' ') return 0; *e=v; q++;
    // perms 4글자
    for(int i=0;i<4;i++){ if(q>=end) return 0; perms[i]=*q++; }
    perms[4]=0;
    return 1;
}

// 탐지 보고 후 종료코드 99.
static void detected(const char* which, u64 vfptr, const char* region){
    emit("VTINT DETECTED ");
    emit(which);
    emit(" vfptr=");
    char hb[20]; hex64(vfptr, hb); emit(hb);
    emit(" region=["); emit(region); emit("]\n");
    k_exit(99);
}

// ---- 진입점 ----------------------------------------------------------------
// 반드시 .text 맨 앞(오프셋 0)에 오도록 다른 외부 호출 없이 단일 함수로 유지.
__attribute__((used, noinline))
void __vtint_check(u64 vtbl){
    // /proc/self/maps 읽기
    char buf[65536];
    i64 fd = k_open("/proc/self/maps", 0 /*O_RDONLY*/);
    i64 total = 0;
    if(fd >= 0){
        for(;;){
            i64 r = k_read(fd, buf+total, (i64)sizeof(buf)-1-total);
            if(r <= 0) break;
            total += r;
            if(total >= (i64)sizeof(buf)-1) break;
        }
        sys3(SYS_close, fd, 0, 0);
    }
    buf[total<0?0:total]=0;

    // vtbl 이 속한 매핑의 perms 찾기
    char region_perms[5] = {'?','?','?','?',0};
    int found = 0;
    const char* p = buf; const char* bend = buf+ (total<0?0:total);
    while(p < bend){
        const char* ls = p;
        while(p<bend && *p!='\n') p++;             // 줄 끝
        const char* le = p;
        if(p<bend) p++;                            // '\n' 건너뜀
        u64 s,e; char perms[5];
        if(parse_line(ls, le, &s, &e, perms)){
            if(vtbl >= s && vtbl < e){
                for(int i=0;i<5;i++) region_perms[i]=perms[i];
                found = 1;
                break;
            }
        }
    }

    // (1) READONLY 검사: 쓰기 가능('w')이면 주입으로 판단
    if(found && region_perms[1]=='w'){
        detected("READONLY", vtbl, region_perms);
    }
    if(!found){
        // 매핑을 못 찾으면 안전하게 탈락 처리
        detected("READONLY", vtbl, "unmapped");
    }

    // (2) ID 검사: 페이지 선두 8바이트 == 주입 ID ?
    u64 page = vtbl & ~((u64)0xFFF);
    u64 id = *(volatile u64*)page;
    if(id != (u64)VTINT_ID){
        detected("ID", vtbl, region_perms);
    }
    // 두 검사 통과 → 아무 일 없이 복귀하여 원래 가상 호출 수행
}
