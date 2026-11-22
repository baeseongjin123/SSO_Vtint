// 객체 생성 전용 번역 단위.
// main 쪽에서는 Base* 만 보이므로 컴파일러가 동적 타입을 확정하지 못하고,
// run() 호출은 반드시 vtable 을 거치는 '진짜 가상 호출'로 남는다.
#include "common.h"
#include <new>

void Base::run() {
    std::printf("BASE RUN\n");
}

void Derived::run() {
    std::printf("DERIVED RUN\n");
}

// 제어 흐름이 탈취되었을 때 실행되는 공격자 함수.
void hijacked() {
    std::printf("HIJACKED\n");
    std::fflush(stdout);
    std::exit(66);
}

// storage 위치에 Derived 를 생성(placement new). 생성자가 vfptr 에
// Derived 의 vtable 주소를 써 넣는다(이 주소를 VRewriter 가 vtsec 으로 패치).
Base* make_derived(void* storage) {
    return new (storage) Derived();
}
