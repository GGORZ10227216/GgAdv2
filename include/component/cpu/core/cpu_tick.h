//
// Created by orzgg on 2021-12-02.
//

#ifndef GGTHUMBTEST_CPU_TICK_H
#define GGTHUMBTEST_CPU_TICK_H

namespace gg_core::gg_cpu {
template<bool CPU_MODE_THUMB, bool REQUIRE_IRQ, bool REQUIRE_DMA, bool REQUIRE_HALT, bool REQUIRE_TIMER>
static void CPUTick_Impl(CPU *self) {
  self->currentInstruction = self->fetchedBuffer[!self->fetchIdx];

  const unsigned condition = [&]() {
	if constexpr (CPU_MODE_THUMB)
	  return 0xE; // AL
	else
	  return (self->currentInstruction & 0xf0000000) >> 28;
  }();

  auto checker = self->conditionChecker[condition];

  if constexpr (REQUIRE_IRQ) {
	Interrupt_impl<E_OperationMode::IRQ>(*self);
  } // if
  else {
	if ((self->*checker)())
	  self->instructionTable[self->iHash(self->currentInstruction)](*self);
	else
	  self->Fetch(self, gg_mem::S_Cycle);
  } // else
} // CPUTick_Impl()

using TickFunctionType = void (*)(CPU *);

template<size_t S>
constexpr static auto GenerateCPUTickHandler()
-> TickFunctionType {
  return CPUTick_Impl<
	  TestBit(S, STATE_BIT::THUMB_BIT),
	  TestBit(S, STATE_BIT::IRQ_BIT),
	  TestBit(S, STATE_BIT::DMA_BIT),
	  TestBit(S, STATE_BIT::HALT_BIT),
	  TestBit(S, STATE_BIT::TIMER_BIT)
  >;
} // GenerateCPUTickHandler()

template<size_t... Ss>
constexpr static auto GenerateCPUTickTable(std::index_sequence<Ss...>)
-> std::array<TickFunctionType, sizeof...(Ss)> {
  constexpr std::array<TickFunctionType, sizeof...(Ss)> result{
	  GenerateCPUTickHandler<Ss>()...
  };

  return result;
}

constexpr static std::array<TickFunctionType, 32> CPUTickTable = GenerateCPUTickTable(std::make_index_sequence<32>{});
}

#endif //GGTHUMBTEST_CPU_TICK_H
