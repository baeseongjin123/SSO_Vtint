// TC3 객체 생성·메서드 정의 (main 과 다른 번역 단위 → 탈가상화 방지).
#include "tc3.h"
#include <cstdlib>
#include <new>

void A::act() { std::printf("TC3 A ACT\n"); }
void B::act() { std::printf("TC3 B ACT\n"); }
void C::act() { std::printf("DERIVED RUN\n"); }   // victim 과 같은 정상 출력

void hijacked() {
    std::printf("HIJACKED\n");
    std::fflush(stdout);
    std::exit(66);
}

A* make_c(void* storage) {
    return new (storage) C();   // 가장 깊은 파생 클래스 C 의 vtable 이 vfptr 에 들어감
}
