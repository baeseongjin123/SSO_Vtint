// TC2 객체 생성·메서드 정의 (main 과 다른 번역 단위 → 탈가상화 방지).
#include "tc2.h"
#include <cstdlib>
#include <new>

void Logger::write()     { std::printf("TC2 LOGGER WRITE\n"); }
void FileLogger::write() { std::printf("DERIVED RUN\n"); }   // victim 과 같은 정상 출력

void hijacked() {
    std::printf("HIJACKED\n");
    std::fflush(stdout);
    std::exit(66);
}

Logger* make_filelogger(void* storage) {
    return new (storage) FileLogger();
}
