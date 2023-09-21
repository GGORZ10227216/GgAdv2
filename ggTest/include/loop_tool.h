//
// Created by buildmachine on 2020-10-27.
//

#include <cstdint>
#include <limits>
#include <type_traits>

#ifndef GGTEST_LOOP_TOOL_H
#define GGTEST_LOOP_TOOL_H

template<typename T>
struct TestField {
  uint64_t value = 0;
  uint64_t limit = std::numeric_limits<T>::max();
  uint64_t step = 1;

  TestField(const T custom_init, const uint64_t custom_limit,
			const T custom_step)requires std::is_integral_v<T> {
	value = custom_init;
	init = custom_init;
	limit = custom_limit;
	step = custom_step;
  }  // TestField()

  void Reset() { value = init; }

private:
  uint64_t init = 0;
};

template<typename F, typename TF>
void TEST_LOOPS(F &f, TF &tf) {
  for (; tf.value <= tf.limit; tf.value += tf.step) {
	f();
  }  // for

  tf.Reset();
}

template<typename F, typename TF, typename... TS>
void TEST_LOOPS(F &f, TF &tf, TS &... ts) {
  for (; tf.value <= tf.limit; tf.value += tf.step) {
	TEST_LOOPS(f, ts...);
  }  // for

  tf.Reset();
}  // LOOPS()

#endif //GGTEST_LOOP_TOOL_H
