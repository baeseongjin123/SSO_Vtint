// vtable 을 많이 만들어 vtsec 이 4KB 를 넘게 하는 정상 프로그램.
//   first | last : 가장 앞/뒤에 배치될 클래스의 가상 호출
#include <cstdio>
#include <cstring>
#include <utility>
struct BigBase { virtual int f0() { return -1; } virtual ~BigBase() {} };
template <int N> struct Big : BigBase {
    int f0() override { return N; }
    virtual int f1() { return N + 1; } virtual int f2() { return N + 2; }
    virtual int f3() { return N + 3; } virtual int f4() { return N + 4; }
    virtual int f5() { return N + 5; } virtual int f6() { return N + 6; }
};
constexpr int kCount = 200;  // vtable 하나 약 80B → 약 16KB
template <int... Is>
static void make_all(BigBase** out, std::integer_sequence<int, Is...>) { ((out[Is] = new Big<Is>()), ...); }
int main(int argc, char** argv) {
    static BigBase* objs[kCount];
    make_all(objs, std::make_integer_sequence<int, kCount>{});
    const char* m = argc > 1 ? argv[1] : "first";
    int sum = 0;
    if (!strcmp(m, "first")) sum = objs[0]->f0();
    else if (!strcmp(m, "last")) sum = objs[kCount - 1]->f0();
    else if (!strcmp(m, "all")) for (BigBase* o : objs) sum += o->f0();
    std::printf("SUM %d\n", sum);
    return 0;
}
