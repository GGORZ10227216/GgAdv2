fp = open("./IOmap", "r")
mapInfos = fp.readlines()
fp.close()


def mode_format(mode_name):
    for char in "\"/":
        mode_name = mode_name.replace(char, "")
    return mode_name


enums = list()
tuples = list()
wave_ram_declare = "std::make_tuple(WAVE_RAM{num}_{hl}, 2, IO_AccessMode::RW)"

for info in mapInfos:
    fields = info.split()
    ignoredTag = ["-", "Not", "?", "(3DS)", "IR"]
    try:
        if len(fields) > 3 and fields[3] not in ignoredTag:
            if fields[3] == "WAVE_RAM":
                waveRamBaseAddr = int(fields[0][:-1], 16)
                for ramNum in range(4):
                    baseAddr2 = waveRamBaseAddr + ramNum * 4
                    tuples.append(wave_ram_declare.format(num=ramNum, hl='L'))
                    enums.append("WAVE_RAM{num}_L = 0x{addr:x}".format(num=ramNum, addr=baseAddr2))
                    tuples.append(wave_ram_declare.format(num=ramNum, hl='H'))
                    enums.append("WAVE_RAM{num}_H = 0x{addr:x}".format(num=ramNum, addr=baseAddr2 + 2))

            else:
                tuples.append("std::make_tuple({name}, {size}, IO_AccessMode::{mode})".format(
                    size=fields[1],
                    mode=mode_format(fields[2]),
                    name=fields[3]
                ))

                enums.append("{name} = 0x{addr}".format(name=fields[3], addr=fields[0][:-1].lower()))
    except:
        print("yee: " + info)


print("enum E_IOName{{\n{}\n}}".format(',\n'.join(enums)))
print("gg_core::make_array(\n{}\n)".format(',\n'.join(tuples)))
