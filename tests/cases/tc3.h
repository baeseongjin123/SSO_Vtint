// TC3: 다단계 상속 A → B → C. 가장 깊은 파생 클래스(C)의 vtable 로 호출해도
// VTint 가 그 vtable 을 옮기고 보호하는지 확인한다. 대상 가상 함수는 slot 0.
#pragma once
#include <cstdio>

struct A {
    virtual void act();   // slot 0 (가상 호출 대상)
    virtual ~A() {}
};
struct B : A {
    void act() override;
};
struct C : B {
    void act() override;  // "DERIVED RUN" (팀원 victim 과 같은 정상 출력)
};

void hijacked();
A* make_c(void* storage);
