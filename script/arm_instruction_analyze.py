from capstone import *
from script.v4Target import *

import json


def ALU(istr, ibin):
    if ibin & (1 << 20):
        istr += 's'

    if ibin & (1 << 25):
        istr += 'i'
    else:
        if ibin & (1 << 4):
            istr += '_shtRs'
        else:
            istr += '_sht'
        istr += {0: 'LSL',
                 1: 'LSR',
                 2: 'ASR',
                 3: 'ROR'
                 }.get((ibin & (0b11 << 5)) >> 5)

    return istr


def PSR(istr, ibin):
    if ibin & (1 << 22):
        istr += '_SPSR'
    else:
        istr += '_CPSR'

    return istr


def Transfer(istr, ibin):
    if ibin & (1 << 25):
        istr += 'i'
    if ibin & (1 << 24):
        istr += 'p'
    if ibin & (1 << 23):
        istr += 'u'
    if ibin & (1 << 22):
        istr += 'b'
    if ibin & (1 << 21):
        istr += 'w'
    if ibin & (1 << 20):
        istr += 'l'
    return istr


def HalfTransfer(istr, ibin):
    if ibin & (1 << 24):
        istr += 'p'
    if ibin & (1 << 23):
        istr += 'u'
    if ibin & (1 << 21):
        istr += 'w'
    if ibin & (1 << 20):
        istr += 'l'
    if ibin & (1 << 6):
        istr += 's'
    if ibin & (1 << 5):
        istr += 'h'

    if ibin & (1 << 22):
        istr += '_immOffset'
    else:
        istr += '_RmOffset'

    return istr


def TransBlock(istr, ibin):
    if ibin & (1 << 24):
        istr += 'p'
    if ibin & (1 << 23):
        istr += 'u'
    if ibin & (1 << 22):
        istr += 's'
    if ibin & (1 << 21):
        istr += 'w'
    if ibin & (1 << 20):
        istr += 'l'

    return istr


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


# firstPass = open("./1stResult", "w+")
# secondPass = open("./2ndResult", "w+")

md = Cs(CS_ARCH_ARM, CS_MODE_ARM)

idict = dict()

analyzeRange = 0x10000000
numOfInstruction = 0
printProgressBar(iteration=0, total=analyzeRange, prefix='Progress({:x},0):'.format(0), suffix='Complete', length=50)
for instruction in range(analyzeRange):
    progress = instruction
    instruction |= 0xe0000000
    istr = ''

    for i in md.disasm(instruction.to_bytes(4, byteorder="little"), 0x0):
        hashResult = ((instruction & 0x0ff00000) >> 16) | ((instruction & 0xf0) >> 4)
        if i.mnemonic in v4ALU:
            istr = ALU(i.mnemonic[:3], instruction)
        elif i.mnemonic in v4PSR:
            istr = PSR(i.mnemonic, instruction)
        elif i.mnemonic in v4Branch:
            istr = i.mnemonic
        elif i.mnemonic in v4MUL:
            istr = i.mnemonic
        elif i.mnemonic in v4MULL:
            istr = i.mnemonic
        elif i.mnemonic in v4Transfer:
            if i.mnemonic[-1] == 'h':
                istr = HalfTransfer(i.mnemonic[:3], instruction)
            else:
                istr = Transfer(i.mnemonic[:3], instruction)
        elif i.mnemonic in v4TransBlock:
            istr = TransBlock(i.mnemonic[:3], instruction)
        elif i.mnemonic == 'swp' or i.mnemonic == 'swpb' or i.mnemonic == 'svc':
            istr = i.mnemonic
        elif i.mnemonic in v4Shift:
            istr = ALU('mov', instruction)

        if not istr == '':
            if hashResult not in idict:
                idict[hashResult] = [istr]
                numOfInstruction = numOfInstruction + 1
            elif istr not in idict[hashResult]:
                idict[hashResult].append(istr)
                numOfInstruction = numOfInstruction + 1

    if progress % 0x10000 == 0:
        printProgressBar(iteration=progress, total=analyzeRange,
                         prefix='Progress({:x},{}):'.format(progress, numOfInstruction),
                         suffix='Complete', length=50)

firstPass = open("./1stResult", "w+")
instruction = list()
for elem in idict.items():
    instruction.append({"hashCode": elem[0], "functionNames": elem[1]})

firstPass.write(json.dumps(instruction))
firstPass.close()
print('\n')
