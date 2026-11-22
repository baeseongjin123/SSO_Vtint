// VTint 검증용 공통 클래스 정의
//
// 가상 함수를 가진 다형성 클래스. vfptr(vtable 포인터)은 객체의 맨 앞 8바이트.
// run()을 '맨 먼저' 선언하여 vtable slot 0 에 배치되도록 한다(Itanium C++ ABI).
#ifndef VTINT_COMMON_H
#define VTINT_COMMON_H

#include <cstdio>
#include <cstdlib>

struct Base {
    // slot 0 : run()  (가상 호출의 대상)
    virtual void run();
    virtual ~Base() {}
};

struct Derived : public Base {
    void run() override;   // "DERIVED RUN" 출력
};

// 공격자 함수: 제어 흐름이 탈취되면 호출된다.
// 보호 전이라면 여기로 흐름이 넘어와 "HIJACKED" 출력 후 종료코드 66.
void hijacked();

// 객체 생성을 별도 번역 단위(factory.cpp)로 분리 → 컴파일러가
// 동적 타입을 알 수 없어 탈가상화(devirtualization)를 하지 못한다.
// 주어진 저장 공간(storage)에 placement-new 로 Derived 를 만들고 Base* 로 반환.
Base* make_derived(void* storage);

#endif // VTINT_COMMON_H
