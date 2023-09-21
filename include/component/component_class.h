//
// Created by orzgg on 2020-09-02.
//

#ifndef GGADV_COMPONENT_CLASS_H
#define GGADV_COMPONENT_CLASS_H

namespace gg_core {
template<typename T>
class ComponentClass {
public :
  ComponentClass(T *ptr) : parent(ptr) {};

protected :
  T *const parent;
};
}

#endif //GGADV_COMPONENT_CLASS_H
