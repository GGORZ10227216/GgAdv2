import sys

from capstone import *
from numba import *
from script.v4Target import *

import json

@jit
def ALU(ibin, rec):
    attr = dict()
    attr['Flags'] = list()
    attr['Type'] = 'alu'

    if ibin & (1 << 20):
        attr['Flags'].append('s')

    if ibin & (1 << 25):
        attr['Flags'].append('i')
        attr['Signature'] = rec['mnemonic'] + ''.join(attr['Flags'])
    else:
        attr['Shift'] = {
            'Amount': {
                0x00: 'Imm',
                0x10: 'Rs'
            }.get(ibin & (1 << 4)),
            'Type': {
                0: 'LSL',
                1: 'LSR',
                2: 'ASR',
                3: 'ROR'
            }.get((ibin & (0b11 << 5)) >> 5)
        }

        attr['Signature'] = rec['mnemonic'] + ''.join(attr['Flags']) + '_' + ''.join(attr['Shift'].values())

    return attr

@jit
def Branch(ibin, rec):
    attr = dict()
    attr['Flags'] = list()
    attr['Type'] = 'branch'

    if ibin & (1 << 27) and ibin & (1 << 24):
        attr['Flags'].append('l')

    attr['Signature'] = rec['mnemonic'] + ''.join(attr['Flags'])
    return attr

@jit
def PSR(ibin, rec):
    attr = dict()
    attr['Flags'] = list()
    attr['Type'] = 'psr'

    if ibin & (1 << 22):
        attr['Flags'].append('p')

    if rec['mnemonic'] == 'msr':
        if ibin & (1 << 25):
            attr['OperandType'] = 'Imm'
        else:
            attr['OperandType'] = 'Rm'
        attr['Signature'] = rec['mnemonic'] + ''.join(attr['Flags']) + '_' + attr['OperandType']
    else:
        attr['Signature'] = rec['mnemonic'] + ''.join(attr['Flags'])

    return attr

@jit
def Mul(ibin, rec):
    attr = dict()
    attr['Type'] = 'mul'
    attr['Flags'] = list()

    if ibin & (1 << 21):
        attr['Flags'].append('a')
    if ibin & (1 << 20):
        attr['Flags'].append('s')

    attr['Signature'] = rec['mnemonic'] + ''.join(attr['Flags'])
    return attr

@jit
def Mull(ibin, rec):
    attr = dict()
    attr['Type'] = 'mull'
    attr['Flags'] = list()

    if ibin & (1 << 22):
        attr['Flags'].append('u')
    if ibin & (1 << 21):
        attr['Flags'].append('a')
    if ibin & (1 << 20):
        attr['Flags'].append('s')

    attr['Signature'] = rec['mnemonic'] + ''.join(attr['Flags'])
    return attr

def Transfer(ibin, rec):
    attr = dict()
    attr['Type'] = 'transfer'
    attr['Flags'] = list()
    if ibin & (1 << 25):
        attr['Flags'].append('i')
    if ibin & (1 << 24):
        attr['Flags'].append('p')
    if ibin & (1 << 23):
        attr['Flags'].append('u')
    if ibin & (1 << 22):
        attr['Flags'].append('b')
    if ibin & (1 << 21):
        attr['Flags'].append('w')
    if ibin & (1 << 20):
        attr['Flags'].append('l')
        attr['Shift'] = {
            'Amount': 'Imm',
            'Type': {
                0: 'LSL',
                1: 'LSR',
                2: 'ASR',
                3: 'ROR'
            }.get((ibin & (0b11 << 5)) >> 5)
        }
        attr['Signature'] = rec['mnemonic'] + ''.join(attr['Flags']) + '_' + ''.join(attr['Shift'].values())
    else:
        attr['Signature'] = rec['mnemonic'] + ''.join(attr['Flags'])

    return attr

def HalfTransfer(ibin, rec):
    attr = dict()
    attr['Type'] = 'half_transfer'
    attr['Flags'] = list()

    if ibin & (1 << 24):
        attr['Flags'].append('p')
    if ibin & (1 << 23):
        attr['Flags'].append('u')
    if ibin & (1 << 21):
        attr['Flags'].append('w')
    if ibin & (1 << 20):
        attr['Flags'].append('l')
    if ibin & (1 << 6):
        attr['Flags'].append('s')
    if ibin & (1 << 5):
        attr['Flags'].append('h')

    if ibin & (1 << 22):
        attr['OffsetType'] = 'Imm'
    else:
        attr['OffsetType'] = 'Rm'

    attr['Signature'] = rec['mnemonic'] + ''.join(attr['Flags']) + '_' + attr['OffsetType']
    return attr

@jit
def TransBlock(ibin, rec):
    attr = dict()
    attr['Type'] = 'block_transfer'
    attr['Flags'] = list()

    if ibin & (1 << 24):
        attr['Flags'].append('p')
    if ibin & (1 << 23):
        attr['Flags'].append('u')
    if ibin & (1 << 22):
        attr['Flags'].append('s')
    if ibin & (1 << 21):
        attr['Flags'].append('w')
    if ibin & (1 << 20):
        attr['Flags'].append('l')

    attr['Signature'] = rec['mnemonic'] + ''.join(attr['Flags'])
    return attr

@jit
def Interrupt(ibin, rec):
    attr = dict()
    attr['Type'] = 'interrupt'
    attr['Signature'] = rec['mnemonic']
    return attr

@jit
def Swap(ibin, rec):
    attr = dict()
    attr['Type'] = 'swap'
    attr['Flags'] = list()

    if ibin & (1 << 22):
        attr['Flags'].append('b')

    attr['Signature'] = rec['mnemonic'] + ''.join(attr['Flags'])
    return attr


# Print iterations progress
def printProgressBar(iteration, total, prefix='', suffix='', decimals=1, length=100, fill='█', printEnd="\r"):
    """
    Call in a loop to create terminal progress bar
    @params:
        iteration   - Required  : current iteration (Int)
        total       - Required  : total iterations (Int)
        prefix      - Optional  : prefix string (Str)
        suffix      - Optional  : suffix string (Str)
        decimals    - Optional  : positive number of decimals in percent complete (Int)
        length      - Optional  : character length of bar (Int)
        fill        - Optional  : bar fill character (Str)
        printEnd    - Optional  : end character (e.g. "\r", "\r\n") (Str)
    """
    percent = ("{0:." + str(decimals) + "f}").format(100 * (iteration / float(total)))
    filledLength = int(length * iteration // total)
    bar = fill * filledLength + '-' * (length - filledLength)
    print(f'\r{prefix} |{bar}| {percent}% {suffix}', end=printEnd)
    # Print New Line on Complete
    if iteration == total:
        print()

md = Cs(CS_ARCH_ARM, CS_MODE_ARM)

@jit
def Analyze(mnemonic, instruction):
    hashResult = ((instruction & 0x0ff00000) >> 16) | ((instruction & 0xf0) >> 4)
    record = {'HashCode': hashResult}
    
    if mnemonic in v4ALU:
        record['mnemonic'] = mnemonic[:3]
        record['Attributes'] = ALU(instruction, record)
    elif mnemonic in v4PSR:
        record['mnemonic'] = mnemonic
        record['Attributes'] = PSR(instruction, record)
    elif mnemonic in v4Branch:
        if mnemonic[-1] == 'x':
            record['mnemonic'] = mnemonic
        else:
            record['mnemonic'] = 'b'
        record['Attributes'] = Branch(instruction, record)
    elif mnemonic in v4MUL:
        record['mnemonic'] = mnemonic[:3]
        record['Attributes'] = Mul(instruction, record)
    elif mnemonic in v4MULL:
        record['mnemonic'] = mnemonic[1:5]
        record['Attributes'] = Mull(instruction, record)
    elif mnemonic in v4Transfer:
        record['mnemonic'] = mnemonic[:3]
        if mnemonic[-1] == 'h':
            record['Attributes'] = HalfTransfer(instruction, record)
        else:
            record['Attributes'] = Transfer(instruction, record)
    elif mnemonic in v4TransBlock:
        record['mnemonic'] = mnemonic[:3]
        record['Attributes'] = TransBlock(instruction, record)
    elif mnemonic == 'swp' or mnemonic == 'swpb':
        record['mnemonic'] = 'swp'
        record['Attributes'] = Swap(instruction, record)
    elif mnemonic in v4Interrupt:
        record['mnemonic'] = 'svc'
        record['Attributes'] = Interrupt(instruction, record)
    elif mnemonic in v4Shift:
        record['mnemonic'] = 'mov'
        record['Attributes'] = ALU(instruction, record)

    return record

def main(argv=None):
    records = list()
    rdict = dict()
    analyzeRange = 0x10000000
    numOfInstruction = 0

    printProgressBar(iteration=0, total=analyzeRange, prefix='Progress({:x},0):'.format(0), suffix='Complete', length=50)
    for instruction in range(analyzeRange):
        progress = instruction
        instruction |= 0xe0000000
        istr = ''

        for i in md.disasm(instruction.to_bytes(4, byteorder="little"), 0x0):
            record = Analyze(i.mnemonic, instruction)

            if 'Attributes' in record.keys():
                if record['HashCode'] in rdict:
                    if record['Attributes']['Signature'] not in rdict[record['HashCode']]:
                        print('hash({:x}), instruction[{}] collide with:\n'.format(
                            record['HashCode'], record['Attributes']['Signature']
                        ))

                        for istr in rdict[record['HashCode']]:
                            print('\t {}', istr)
                else:
                    rdict[record['HashCode']] = list()
                    rdict[record['HashCode']].append(record['Attributes']['Signature'])
                    records.append(record)
                    numOfInstruction += 1

        if progress % 0x10000 == 0:
            printProgressBar(iteration=progress, total=analyzeRange,
                            prefix='Progress({:x},{}):'.format(progress, numOfInstruction),
                            suffix='Complete', length=50)

    firstPass = open("1stResult.json", "w+")

    cnt = 1
    for record in records:
        record['#instruction'] = cnt
        cnt += 1
    firstPass.write(json.dumps(records))
    firstPass.close()

    print('\n')

if __name__ == "__main__":
    sys.exit(main())