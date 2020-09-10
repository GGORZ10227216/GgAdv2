//
// Created by orzgg on 2020-09-02.
//

#include <cstdint>
#include <cstdlib>
#include <string>

#ifndef GGADV_INSTRUCTION_CLASS_H
#define GGADV_INSTRUCTION_CLASS_H

namespace gg_core {
    template<typename T>
    class InstructionClass {
    public :
        void SetRegisterRef(uint32_t binaryInstr) {
            static_cast<T *> (this)->SetRegisterRefImpl(binaryInstr);
        } // SetRegisterRef()

        void Execute() {
            static_cast<T *> (this)->ExecuteImpl();
        } // Execute()

        std::string Disassemble() {
            return "";
        } // Disassemble()

    private :
        void SetRegisterRefImpl(uint32_t binaryInstr) {}

        void ExecuteImpl() {}
    };
}

#endif //GGADV_INSTRUCTION_CLASS_H
