//
// Created by orzgg on 2021-12-13.
//

#include <cstdint>
#include <functional>

#ifndef GGTHUMBTEST_TASK_H
#define GGTHUMBTEST_TASK_H

struct Task {
    size_t id ;
    uint64_t timeStamp ;
    std::function<void(int)> content ;
};

#endif //GGTHUMBTEST_TASK_H
