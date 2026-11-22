// 정상 입력만 처리하는 프로그램. 보호 후에도 결과가 같고 VTINT DETECTED 가 없어야 한다.
//   base | derived | other | multi | multi_base2 | repeat
#include <cstring>
#include "fp_classes.h"
int main(int argc, char** argv) {
    const char* m = argc > 1 ? argv[1] : "derived";
    if (!strcmp(m, "base"))    { Base* b = make_base(); b->run(); }
    else if (!strcmp(m, "derived")) { Base* b = make_derived(); b->run(); }
    else if (!strcmp(m, "other"))   { Other* o = make_other(); o->other(); }
    else if (!strcmp(m, "multi"))   { Base* b = make_multi(); b->run(); }
    else if (!strcmp(m, "multi_base2")) { Second* s = make_multi(); s->second(); }  // 2차 vptr
    else if (!strcmp(m, "repeat")) {
        Base* b = make_derived();
        for (int i = 0; i < 1000; i++) b->run();
    } else { std::fprintf(stderr, "unknown mode\n"); return 2; }
    return 0;
}
