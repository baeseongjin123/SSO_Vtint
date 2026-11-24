// 13주차 확장 검증용 클래스 모음.
// 객체 생성·메서드 정의는 w13_factory.cpp (다른 번역 단위 → 탈가상화 방지).
#pragma once
#include <cstdio>
#include <stdexcept>

// 단일 상속, 여러 슬롯 (slot 0~3 + 소멸자)
struct Base {
    virtual void f0();
    virtual void f1();
    virtual void f2();
    virtual void f3();
    virtual long sum6(long a, long b, long c, long d, long e);  // 인자 5개 + this
    virtual ~Base();
};
struct Derived : Base {
    void f0() override;
    void f1() override;
    void f2() override;
    void f3() override;
    long sum6(long a, long b, long c, long d, long e) override;
    ~Derived() override;
};

// 슬롯이 많은 클래스 (slot 20 → vtable 안 오프셋 0xa0, 큰 displacement)
struct Wide {
    virtual void w00(); virtual void w01(); virtual void w02(); virtual void w03();
    virtual void w04(); virtual void w05(); virtual void w06(); virtual void w07();
    virtual void w08(); virtual void w09(); virtual void w10(); virtual void w11();
    virtual void w12(); virtual void w13(); virtual void w14(); virtual void w15();
    virtual void w16(); virtual void w17(); virtual void w18(); virtual void w19();
    virtual void w20();
    virtual ~Wide() {}
};

// 다중 상속 3개 부모 → vptr 3개 (1차 + 2차 + 3차)
struct PA { virtual void pa(); virtual ~PA() {} long a = 1; };
struct PB { virtual void pb(); virtual ~PB() {} long b = 2; };
struct PC { virtual void pc(); virtual ~PC() {} long c = 3; };
struct M3 : PA, PB, PC { void pa() override; void pb() override; void pc() override; };

// 가상 상속 (다이아몬드) → vbase offset, construction vtable, VTT
struct VB { virtual void vb(); virtual ~VB() {} long v = 7; };
struct VL : virtual VB { virtual void vl(); };
struct VR : virtual VB { virtual void vr(); };
struct VD : VL, VR { void vb() override; void vl() override; void vr() override; };

// 추상 클래스 (순수 가상 함수 → vtable 에 __cxa_pure_virtual, 외부 심볼)
struct Shape { virtual int area() = 0; virtual ~Shape() {} };
struct Square : Shape { int s = 3; int area() override; };

// 라이브러리 클래스 상속: what() 을 재정의하지 않음 → vtable 에 libstdc++ 함수 주소
struct MyErr : std::runtime_error { MyErr() : std::runtime_error("MYERR WHAT") {} };

Base*   make_base();
Base*   make_derived();
Wide*   make_wide();
M3*     make_m3();
VD*     make_vd();
Shape*  make_square();
std::exception* make_myerr();
extern Derived g_static_derived;   // 전역 객체 (main 이전 정적 초기화로 생성)
