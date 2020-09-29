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
        'HalfMemAccess_impl<{}, {}, {}, {}, {}, {}, OFFSET_TYPE::{}>(instance) ;'

    tags = {}

    if "p" in record["Attribute"]["Flags"]:
        tags["P"] = "true"
    else:
        tags["P"] = "false"

    if "u" in record["Attribute"]["Flags"]:
        tags["U"] = "true"
    else:
        tags["U"] = "false"

    if "w" in record["Attribute"]["Flags"]:
        tags["W"] = "true"
    else:
        tags["W"] = "false"

    if "l" in record["Attribute"]["Flags"]:
        tags["L"] = "true"
    else:
        tags["L"] = "false"

    if "s" in record["Attribute"]["Flags"]:
        tags["S"] = "true"
    else:
        tags["S"] = "false"

    if "h" in record["Attribute"]["Flags"]:
        tags["H"] = "true"
    else:
        tags["H"] = "false"

    tags["offsettype"] = record["Attribute"]["OffsetType"].upper()

    signature = signature.format(
        tags["P"],
        tags["U"],
        tags["W"],
        tags["L"],
        tags["S"],
        tags["H"],
        tags["offsettype"]
    )

    return signature


def printHeader(outputFile, headerName):
    outputFile.write('#include <{}>\n'.format(headerName))


with open('./result.json', 'r') as inputFile, open('{}/v4_half_transfer_implement.h'.format(headerPath), 'w+') as outputFile:
    records = json.load(inputFile)
    chkList = list()

    for header in transfer_required_Header:
        printHeader(outputFile, header)

    outputFile.write('\nnamespace gg_core::gg_cpu {\n')
    for record in records:
        if record['Attribute']['TypeName'] == 'half_transfer' and record['Attribute']['Signature'] not in chkList:
            outputFile.write('\tstatic void {}({}) {{\n\t\t{}\n\t}}\n\n'.format(
                record['Attribute']['Signature'], args, transGen(record))
            )
            chkList.append(record['Attribute']['Signature'])
    outputFile.write('} // gg_core::gg_cpu\n')

