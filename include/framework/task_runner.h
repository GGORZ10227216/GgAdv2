//
// Created by orzgg on 2021-11-29.
//

#include <array>
#include <functional>
#include <queue>

#include <task.h>

#ifndef GGTHUMBTEST_TASK_RUNNER_H
#define GGTHUMBTEST_TASK_RUNNER_H

constexpr static int maxTaskNumber = 64;

template<size_t I>
class TaskRunner {
public:
  TaskRunner(uint64_t &sysClk) :
	  _systemClk(sysClk) {
	for (int i = 0; i < c.size(); ++i)
	  c[i] = new Task();
  } // TaskQueue()

  ~TaskRunner() {
	for (int i = 0; i < c.size(); ++i)
	  delete c[i];
  } // ~TaskQueue()

  void Step(int cycles) {
	// slightly different with nanoboy, not sure it's ok or not......
	_systemClk += cycles;
	while (pendingTaskNum != 0 && c[0]->timestamp <= _systemClk) {
	  auto currentTask = c[0];
	  currentTask->job(_systemClk - currentTask->timestamp);
	  Cancel(0);
	} // while
  } // Step()

  Task *Schedule(uint64_t delayedClk, const std::function<void(int)> &newContent) {
	if (pendingTaskNum + 1 >= I) {
	  spdlog::error("Reached the limit of task queue");
	  exit(-1);
	} // if
	else {
	  int n = pendingTaskNum++;
	  int p = Parent(n);

	  Task *newTask = c[n];
	  c[n]->content = newContent;
	  c[n]->timeStamp = _systemClk;

	  if (n != 0) {
		while (c[n]->timeStamp < c[p]->timeStamp) {
		  Swap(n, p);
		  n = p;
		  p = Parent(n);
		} // while
	  } // else

	  return newTask;
	} // else
  } // Schedule()

  void Cancel(size_t i) {
	pendingTaskNum = pendingTaskNum - 1;
	Swap(i, pendingTaskNum);

	size_t p = Parent(i);
	if (i != 0 && c[i]->timeStamp < c[p]->timeStamp) {
	  // bottom-up
	  while (i != 0 && c[i]->timeStamp < c[p]->timeStamp) {
		Swap(i, p);
		i = p;
		p = Parent(i);
	  } // while
	} // if
	else {
	  // top-down
	  Heapify_TopDown(i);
	} // else
  } // Cancel()

private:
  inline size_t Parent(size_t i) { return i / 2; }
  inline size_t LeftChild(size_t i) { return i * 2 + 1; };
  inline size_t RightChild(size_t i) { return i * 2 + 2; };

  void Swap(size_t i, size_t j) {
	Task *tmp = c[i];
	c[i] = c[j];
	c[j] = tmp;
	c[i]->id = i;
	c[j]->id = j;
  } // Swap()

  void Heapify_TopDown(size_t i) {
	int lNodeIdx = LeftChild(i);
	int rNodeIdx = RightChild(i);

	if (lNodeIdx < pendingTaskNum && c[i]->timeStamp > c[lNodeIdx]->timeStamp) {
	  Swap(i, lNodeIdx);
	  Heapify_TopDown(lNodeIdx);
	} // if

	if (rNodeIdx < pendingTaskNum && c[i]->timeStamp > c[rNodeIdx]->timeStamp) {
	  Swap(i, rNodeIdx);
	  Heapify_TopDown(rNodeIdx);
	} // if
  } // Heapify_TopDown()

  std::array<Task *, I> c;
  int pendingTaskNum = 0;
  uint64_t &_systemClk;
};

#endif //GGTHUMBTEST_TASK_RUNNER_H
