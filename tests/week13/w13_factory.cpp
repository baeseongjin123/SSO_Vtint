#include "w13.h"

void Base::f0() { std::puts("BASE F0"); }
void Base::f1() { std::puts("BASE F1"); }
void Base::f2() { std::puts("BASE F2"); }
void Base::f3() { std::puts("BASE F3"); }
long Base::sum6(long a, long b, long c, long d, long e) { return a + b + c + d + e; }
Base::~Base() {}
void Derived::f0() { std::puts("DERIVED F0"); }
void Derived::f1() { std::puts("DERIVED F1"); }
void Derived::f2() { std::puts("DERIVED F2"); }
void Derived::f3() { std::puts("DERIVED F3"); }
long Derived::sum6(long a, long b, long c, long d, long e) { return a + 2 * b + 3 * c + 4 * d + 5 * e; }
Derived::~Derived() { std::puts("DERIVED DTOR"); }

#define W(n) void Wide::w##n() { std::puts("WIDE W" #n); }
W(00) W(01) W(02) W(03) W(04) W(05) W(06) W(07) W(08) W(09)
W(10) W(11) W(12) W(13) W(14) W(15) W(16) W(17) W(18) W(19) W(20)

void PA::pa() { std::puts("PA"); }
void PB::pb() { std::puts("PB"); }
void PC::pc() { std::puts("PC"); }
void M3::pa() { std::puts("M3 PA"); }
void M3::pb() { std::printf("M3 PB b=%ld\n", b); }
void M3::pc() { std::printf("M3 PC c=%ld\n", c); }

void VB::vb() { std::puts("VB"); }
void VL::vl() { std::puts("VL"); }
void VR::vr() { std::puts("VR"); }
void VD::vb() { std::printf("VD VB v=%ld\n", v); }
void VD::vl() { std::puts("VD VL"); }
void VD::vr() { std::puts("VD VR"); }

int Square::area() { return s * s; }

Base*   make_base()    { return new Base(); }
Base*   make_derived() { return new Derived(); }
Wide*   make_wide()    { return new Wide(); }
M3*     make_m3()      { return new M3(); }
VD*     make_vd()      { return new VD(); }
Shape*  make_square()  { return new Square(); }
std::exception* make_myerr() { return new MyErr(); }
Derived g_static_derived;
