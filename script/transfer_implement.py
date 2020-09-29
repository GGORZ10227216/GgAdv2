import json

# Output example:

#static void and_ImmLSL(GbaInstance &instance) {
#   alu_impl<true, false, SHIFT_BY::IMM, SHIFT_TYPE::LSL, OP_TYPE::LOGICAL>(instance,
#       [](uint32_t Rn, uint32_t op2, bool carry) {
#           return static_cast<uint64_t>(Rn) + op2 ;
#       }
#   );
#}

transfer_required_Header = ['bit_manipulate.h', 'v4_mem_api.h']
headerPath = '../include/instruction/arm'
args = 'GbaInstance& instance'

def transGen(record):
    signature = \
        'MemAccess_impl<{}, {}, {}, {}, {}, {}, SHIFT_TYPE::{}>(instance) ;'

    tags = {}
    if "i" not in record["Attribute"]["Flags"]:
        tags["I"] = "false"
        tags["shttype"] = "NONE"
    else:
        tags["I"] = "true"
        tags["shttype"] = record["Attribute"]["Shift"]["Type"]

    if "p" in record["Attribute"]["Flags"]:
        tags["P"] = "true"
    else:
        tags["P"] = "false"

    if "u" in record["Attribute"]["Flags"]:
        tags["U"] = "true"
    else:
        tags["U"] = "false"

    if "b" in record["Attribute"]["Flags"]:
        tags["B"] = "true"
    else:
        tags["B"] = "false"

    if "w" in record["Attribute"]["Flags"]:
        tags["W"] = "true"
    else:
        tags["W"] = "false"

    if "l" in record["Attribute"]["Flags"]:
        tags["L"] = "true"
    else:
        tags["L"] = "false"

    signature = signature.format(
        tags["I"],
        tags["P"],
        tags["U"],
        tags["B"],
        tags["W"],
        tags["L"],
        tags["shttype"]
    )

    return signature


def printHeader(outputFile, headerName):
    outputFile.write('#include <{}>\n'.format(headerName))


with open('./result.json', 'r') as inputFile, open('{}/v4_transfer_implement.h'.format(headerPath), 'w+') as outputFile:
    records = json.load(inputFile)
    chkList = list()

    for header in transfer_required_Header:
        printHeader(outputFile, header)

    outputFile.write('\nnamespace gg_core::gg_cpu {\n')
    for record in records:
        if record['Attribute']['TypeName'] == 'transfer' and record['Attribute']['Signature'] not in chkList:
            outputFile.write('\tstatic void {}({}) {{\n\t\t{}\n\t}}\n\n'.format(
                record['Attribute']['Signature'], args, transGen(record))
            )
            chkList.append(record['Attribute']['Signature'])
    outputFile.write('} // gg_core::gg_cpu\n')

