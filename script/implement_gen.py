import json
import sys

headerPath = '../include/instruction/arm'
args = 'GbaInstance& instance'

fileList = {
    "branch": [0, open('{}/v4_branch_implement.h'.format(headerPath), 'w+')],
    "psr": [0, open('{}/v4_psr_implement.h'.format(headerPath), 'w+')],
    "mul": [0, open('{}/v4_mul_implement.h'.format(headerPath), 'w+')],
    "mull": [0, open('{}/v4_mull_implement.h'.format(headerPath), 'w+')],
    "half_transfer": [0, open('{}/v4_half_transfer_implement.h'.format(headerPath), 'w+')],
    "block_transfer": [0, open('{}/v4_block_transfer_implement.h'.format(headerPath), 'w+')],
    "swap": [0, open('{}/v4_swap_implement.h'.format(headerPath), 'w+')],
    "interrupt": [0, open('{}/v4_interrupt_implement.h'.format(headerPath), 'w+')]
}

with open('result.json', 'r') as inputFile:
    records = json.load(inputFile)
    chkList = list()

    for record in records:
        typeName = record['Attribute']['TypeName']
        if typeName in fileList:
            outputFile = fileList[typeName][1]
            if fileList[typeName][0] == 0:
                outputFile.write('namespace gg_core::gg_cpu {\n')
                fileList[typeName][0] = 1

            if record['Attribute']['Signature'] not in chkList:
                outputFile.write('\tstatic void {}({}) {{}}\n'.format(
                    record['Attribute']['Signature'], args)
                )
                chkList.append(record['Attribute']['Signature'])

    for file in fileList.values():
        file[1].write('} // gg_core::gg_cpu\n')
        file[1].close()
