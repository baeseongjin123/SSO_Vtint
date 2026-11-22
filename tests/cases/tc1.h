// TC1: 단일 상속, 대상 가상 함수가 vtable slot 0, 스택에 놓인 객체.
// 팀원 victim 과 같은 인터페이스(normal/inject/rodata)를 따르는 취약 대상 프로그램.
#pragma once
#include <cstdio>

struct Shape {
    virtual void draw();   // 맨 먼저 선언 → vtable slot 0 (가상 호출 대상)
    virtual ~Shape() {}
};

struct Rect : Shape {
    void draw() override;  // "DERIVED RUN" (팀원 victim 과 같은 정상 출력)
};

// 제어 흐름이 탈취되면 실행되는 공격자 함수.
void hijacked();

// 객체 생성을 별도 번역 단위로 분리 → 컴파일러가 동적 타입을 몰라 탈가상화하지 못함.
Shape* make_rect(void* storage);
