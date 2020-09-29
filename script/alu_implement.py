import json

# Output example:

#static void and_ImmLSL(GbaInstance &instance) {
#   alu_impl<true, false, SHIFT_BY::IMM, SHIFT_TYPE::LSL, OP_TYPE::LOGICAL>(instance,
#       [](uint32_t Rn, uint32_t op2, bool carry) {
#           return static_cast<uint64_t>(Rn) + op2 ;
#       }
#   );
#}

alu_required_Header = ['bit_manipulate.h', 'v4_alu_api.h']
headerPath = '../include/instruction/arm'
args = 'GbaInstance& instance'

logical = ["AND", "EOR", "ORR", "MOV", "BIC", "MVN"]
test = ["TST", "TEQ", "CMP", "CMN"]

handlerTable = {
    "AND": "return static_cast<uint64_t>(Rn) & op2 ;",
    "EOR": "return static_cast<uint64_t>(Rn) ^ op2 ;",
    "SUB": "return static_cast<uint64_t>(Rn) - op2 ;",
    "RSB": "return static_cast<uint64_t>(op2) - Rn ;",
    "ADD": "return static_cast<uint64_t>(Rn) + op2 ;",
    "ADC": "return static_cast<uint64_t>(Rn) + op2 + carry ;",
    "SBC": "return static_cast<uint64_t>(Rn) - op2 + carry - 1 ;",
    "RSC": "return static_cast<uint64_t>(op2) - Rn + carry - 1 ;",
    "TST": "return static_cast<uint64_t>(Rn) & op2 ;",
    "TEQ": "return static_cast<uint64_t>(Rn) ^ op2 ;",
    "CMP": "return static_cast<uint64_t>(Rn) - op2 ;",
    "CMN": "return static_cast<uint64_t>(Rn) + op2 ;",
    "ORR": "return static_cast<uint64_t>(Rn) | op2 ;",
    "MOV": "return static_cast<uint64_t>(op2) ;",
    "BIC": "return static_cast<uint64_t>(Rn) & (~op2) ;",
    "MVN": "return ~static_cast<uint64_t>(op2);"
}

def aluGen(record):
    mnemonic = record['Attribute']['Signature'][:3].upper()
    signature = \
        'Alu_impl<{}, {}, SHIFT_BY::{}, SHIFT_TYPE::{}, OP_TYPE::{}> (instance,\n' \
        '\t\t\t[](uint32_t Rn, uint32_t op2, bool carry) {{\n' \
        '\t\t\t\t{}\n' \
        '\t\t\t}}\n' \
        '\t\t);'

    tags = {}
    if "i" in record["Attribute"]["Flags"]:
        tags["I"] = "false"
        tags["shtby"] = "NONE"
        tags["shttype"] = "NONE"
    else:
        tags["I"] = "true"
        tags["shtby"] = record["Attribute"]["Shift"]["Amount"].upper()
        tags["shttype"] = record["Attribute"]["Shift"]["Type"]

    if "s" in record["Attribute"]["Flags"]:
        tags["S"] = "true"
    else:
        tags["S"] = "false"

    if mnemonic in logical:
        tags["optype"] = "LOGICAL"
    elif mnemonic in test:
        tags["optype"] = "TEST"
    else:
        tags["optype"] = "ARITHMETIC"

    signature = signature.format(
        tags["I"],
        tags["S"],
        tags["shtby"],
        tags["shttype"],
        tags["optype"],
        handlerTable[mnemonic]
    )

    return signature


def printHeader(outputFile, headerName):
    outputFile.write('#include <{}>\n'.format(headerName))


with open('./result.json', 'r') as inputFile, open('{}/v4_alu_implement.h'.format(headerPath), 'w+') as outputFile:
    records = json.load(inputFile)
    chkList = list()

    for header in alu_required_Header:
        printHeader(outputFile, header)

    outputFile.write('\nnamespace gg_core::gg_cpu {\n')
    for record in records:
        if record['Attribute']['TypeName'] == 'alu' and record['Attribute']['Signature'] not in chkList:
            outputFile.write('\tstatic void {}({}) {{\n\t\t{}\n\t}}\n\n'.format(
                record['Attribute']['Signature'], args, aluGen(record))
            )
            chkList.append(record['Attribute']['Signature'])
    outputFile.write('} // gg_core::gg_cpu\n')

