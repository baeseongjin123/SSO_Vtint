#include "fp_classes.h"
void Base::run()      { std::puts("BASE RUN"); }
void Derived::run()   { std::puts("DERIVED RUN"); }
void Other::other()   { std::puts("OTHER RUN"); }
void Second::second() { std::puts("SECOND RUN"); }
void Multi::run()     { std::puts("MULTI RUN"); }
void Multi::second()  { std::puts("MULTI SECOND RUN"); }
Base*  make_base()    { return new Base(); }
Base*  make_derived() { return new Derived(); }
Other* make_other()   { return new Other(); }
Multi* make_multi()   { return new Multi(); }
