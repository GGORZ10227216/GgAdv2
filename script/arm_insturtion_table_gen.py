import json
from script.v4Target import *

headerPath = '../include/instruction/arm'


class Header:
    def __init__(self, name, mode):
        self.file = open(name, mode)
        self.file.write('#include <array>\n\n')
        #self.file.write('#include <gba_instance.h>\n\n')
        self.file.write('namespace gg_core::gg_cpu {\n')

        self.signatures = list()

    def __del__(self):
        self.file.write('} // gg_core::gg_cpu\n')
        self.file.close()

    def AddDefinition(self, defName, parameter):
        if defName not in self.signatures:
            newSignature = '\tstatic void {}({}) '.format(defName, args)
            self.file.write(newSignature + '{}\n')
            prototype.write('\t' + newSignature + ';\n')
            self.signatures.append(defName)


analyzedData = open('./1stResult', "r")
headerOut = open('{}/arm_instruction_table.h'.format(headerPath), 'w+')
instructions = json.loads(analyzedData.read())

headerDict = dict()
for i in instructions:
    # print('{:x}->{}'.format(i['hashCode'], i['functionNames']))
    headerDict[i['hashCode']] = i['functionNames']

headerOut.write('#include <array>\n#include <arm_prototype.h>\n\nnamespace gg_core::gg_cpu {\n')
headerOut.write('\tusing InstructionHandler = void(*)(GbaInstance&);\n\n')
headerOut.write('\tconstexpr static std::array<InstructionHandler, 4096> armHandlers {\n')
instCnt = 0

v4_implements = {
    v4Type.ALU: Header('{}/v4_alu_implement.h'.format(headerPath), 'w+'),
    v4Type.PSR: Header('{}/v4_psr_implement.h'.format(headerPath), 'w+'),
    v4Type.Branch: Header('{}/v4_branch_implement.h'.format(headerPath), 'w+'),
    v4Type.MUL: Header('{}/v4_mul_implement.h'.format(headerPath), 'w+'),
    v4Type.MULL: Header('{}/v4_mull_implement.h'.format(headerPath), 'w+'),
    v4Type.TRANS: Header('{}/v4_transfer_implement.h'.format(headerPath), 'w+'),
    v4Type.MTRANS: Header('{}/v4_btransfer_implement.h'.format(headerPath), 'w+'),
    v4Type.SWP: Header('{}/v4_swp_implement.h'.format(headerPath), 'w+'),
    v4Type.IRT: Header('{}/v4_interrupt_implement.h'.format(headerPath), 'w+')
}

args = 'GbaInstance& instance'

prototype = open('{}/arm_prototype.h'.format(headerPath), 'w+')
prototype.write('namespace gg_core {\n')
prototype.write('\tclass GbaInstance;\n\n')
prototype.write('\tnamespace gg_cpu {\n')

v4_implements[v4Type.ALU].AddDefinition('undefined', args)

for i in range(4096):
    instCnt += 1
    if i in headerDict:
        funcName = headerDict[i][0]
        headerOut.write(funcName.rjust(20))
        if funcName[:3] in v4ALU:
            v4_implements[v4Type.ALU].AddDefinition(funcName, args)
        elif funcName[:3] in v4PSR:
            v4_implements[v4Type.PSR].AddDefinition(funcName, args)
        elif funcName in v4Branch:
            v4_implements[v4Type.Branch].AddDefinition(funcName, args)
        elif funcName in v4MUL:
            v4_implements[v4Type.MUL].AddDefinition(funcName, args)
        elif funcName in v4MULL:
            v4_implements[v4Type.MULL].AddDefinition(funcName, args)
        elif funcName[:3] in v4Transfer:
            v4_implements[v4Type.TRANS].AddDefinition(funcName, args)
        elif funcName[:3] in ['ldm', 'stm']:
            v4_implements[v4Type.MTRANS].AddDefinition(funcName, args)
        elif funcName[:3] == 'swp':
            v4_implements[v4Type.SWP].AddDefinition(funcName, args)
        elif funcName == 'svc':
            v4_implements[v4Type.IRT].AddDefinition(funcName, args)
        else:
            print('{}?', funcName)
    else:
        headerOut.write('undefined'.rjust(20))
    if not i == 4095:
        headerOut.write(',')
        if instCnt % 8 == 0:
            headerOut.write('\n')
headerOut.write('\n\t};\n} // gg_core::gg_cpu\n')
headerOut.close()

prototype.write('\t\tstatic void undefined(GbaInstance& instance) ;\n')
prototype.write('\t} // gg_cpu\n')
prototype.write('} // gg_core\n')
prototype.close()
