import json
from script.v4Target import *

headerPath = '../include/instruction/arm'
args = 'GbaInstance& instance'

with open('./result.json', 'r') as recordfile:
    records = json.load(recordfile)
    idict = dict()
    typeTable = dict()

    for i in range(4096):
        typeTable[i] = 'undefined'

    for record in records:
        if record['Attribute']['Signature'] not in idict:
            idict[record['Attribute']['Signature']] = list()
        idict[record['Attribute']['Signature']].append(record['Hash'])

    with open('{}/arm_prototype.h'.format(headerPath), 'w+') as prototypeFile:
        prototypeFile.write('namespace gg_core {\n\tclass GbaInstance;\n\n')
        prototypeFile.write('\tnamespace gg_cpu {\n')
        for signature in idict.keys():
            prototypeFile.write('\t\tstatic void {}({}) ;\n'.format(signature, args))
            for hashCode in idict[signature]:
                typeTable[hashCode] = signature
        prototypeFile.write('\t\tstatic void undefined({}) ;\n'.format(args))
        prototypeFile.write('\t} // gg_cpu\n} // gg_core\n')

    with open('{}/arm_instruction_table.h'.format(headerPath), 'w+') as table:
        cnt = 1
        table.write('#include <array>\n#include <arm_prototype.h>\n\n')
        table.write('namespace gg_core::gg_cpu {\n')
        table.write('\tusing InstructionHandler = void(*)(GbaInstance&) ;\n\n')
        table.write('\tconstexpr static std::array<InstructionHandler, 4096> armHandlers {\n')
        for instruction in typeTable.values():
            table.write('{}'.format(instruction).rjust(20))
            if cnt != 4096:
                table.write(',')
            if cnt % 8 == 0:
                table.write('\n')
            cnt += 1
        table.write('\t};\n}\n')


