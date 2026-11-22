// E. 오탐 검사용 정상 프로그램 공통 클래스 (Base/Derived/Other/Multi — 11주차 기능 1 구성)
#pragma once
#include <cstdio>
struct Base    { virtual void run();    virtual ~Base() {} };
struct Derived : Base { void run() override; };
struct Other   { virtual void other();  virtual ~Other() {} };
struct Second  { virtual void second(); virtual ~Second() {} };
struct Multi   : Base, Second { void run() override; void second() override; };
// 객체 생성은 별도 번역 단위 (탈가상화 방지)
Base*   make_base();
Base*   make_derived();
Other*  make_other();
Multi*  make_multi();
