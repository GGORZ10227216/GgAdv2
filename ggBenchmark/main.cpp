//
// Created by jason4_lee on 2020-10-07.
//

#include <benchmark/benchmark.h>
#include <emu_framework.h>

static void ALU_PerformanceTest(benchmark::State& state) {
    for (auto _ : state) {
        gg_core::GbaInstance emu(std::nullopt) ;
    } // for
}
// Register the function as a benchmark
BENCHMARK(ALU_PerformanceTest);

BENCHMARK_MAIN();