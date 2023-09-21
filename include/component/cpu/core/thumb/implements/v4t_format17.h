//
// Created by orzgg on 2021-07-07.
//

#ifndef GGTEST_V4T_FORMAT17_H
#define GGTEST_V4T_FORMAT17_H

namespace gg_core::gg_cpu {
extern void SoftInterrupt(CPU &instance) {
  Interrupt_impl<SVC>(instance);
} // SoftInterrupt()
}

#endif //GGTEST_V4T_FORMAT17_H
