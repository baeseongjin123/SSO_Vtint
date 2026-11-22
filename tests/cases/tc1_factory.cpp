// TC1 객체 생성·메서드 정의 (main 과 다른 번역 단위 → 탈가상화 방지).
#include "tc1.h"
#include <cstdlib>
#include <new>

void Shape::draw() { std::printf("TC1 SHAPE DRAW\n"); }
void Rect::draw()  { std::printf("DERIVED RUN\n"); }   // victim 과 같은 정상 출력

void hijacked() {
    std::printf("HIJACKED\n");
    std::fflush(stdout);
    std::exit(66);
}

Shape* make_rect(void* storage) {
    return new (storage) Rect();   // 생성자가 vfptr 에 Rect 의 vtable 주소점을 써 넣음
}
