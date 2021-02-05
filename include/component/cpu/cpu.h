//
// Created by orzgg on 2020-09-02.
//

#include <array>

#include <component_class.h>
#include <cpu_enum.h>
#include <status.h>

#include <arm_decoder.h>

#ifndef GGADV_CPU_H
#define GGADV_CPU_H

namespace gg_core {
    class GbaInstance;

    namespace gg_cpu {
        class CPUCore : public Status {

        public :
            CPUCore(gg_mem::MMU &parentMMU) : _mem(parentMMU) {}

            void Tick() {
                if (TestBit(_cpsr, E_PSRBit::T) == 0) {
                    currentInstruction = fetchedBuffer[pipelineCnt];
                    Fetch<ARM>();

                    uint32_t hash = ((currentInstruction & 0x0ff00000) >> 16) |
                                    ((currentInstruction & 0xf0) >> 4);
                    gg_cpu::armHandlers[hash](*this);
                } // if
                else {

                } // else 
            } // Tick()

            void TickImpl() = delete;

            template<E_CpuMode CMODE>
            void RefillPipeline() {
                uint32_t pcBase;
                if constexpr (CMODE == E_CpuMode::ARM) {
                    pcBase = (_regs[pc] & ~0x3);
                    fetchedBuffer[0] = _mem.Read32(pcBase);
                    fetchedBuffer[1] = _mem.Read32(pcBase + 4);
                } // if
                else {
                    pcBase = (_regs[pc] & ~0x1);
                    fetchedBuffer[0] = _mem.Read16(pcBase);
                    fetchedBuffer[1] = _mem.Read16(pcBase + 2);
                } // else
            } // RefillPipeline()

        private :
            gg_mem::MMU &_mem ;

            template<E_CpuMode CMODE>
            void Fetch() {
                if constexpr (CMODE == E_CpuMode::ARM) {
                    _regs[pc] += 4;
                    pipelineCnt = (pipelineCnt + 1) % fetchedBuffer.size();
                    fetchedBuffer[pipelineCnt] = _mem.Read32(_regs[pc]);
                } // if
                else {
                    _regs[pc] += 2;
                    pipelineCnt = (pipelineCnt + 1) % fetchedBuffer.size();
                    fetchedBuffer[pipelineCnt] = _mem.Read16(_regs[pc]);
                } // else
            } // Fetch()
        };
    }
}

#endif //GGADV_CPU_H
