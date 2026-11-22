// TC2: tc1(스택)과 달리 객체를 힙에 두는 경우. 다른 클래스 계층(Logger/FileLogger), 대상 가상 함수 slot 0.
// 객체가 힙에 있어도 탐지되는지, 그리고 다른 vtable 도 보호되는지 확인.
#pragma once
#include <cstdio>

struct Logger {
    virtual void write();   // slot 0 (가상 호출 대상)
    virtual ~Logger() {}
};

struct FileLogger : Logger {
    void write() override;  // "DERIVED RUN" (팀원 victim 과 같은 정상 출력)
};

void hijacked();
Logger* make_filelogger(void* storage);
