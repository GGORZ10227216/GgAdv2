import sys

if len(sys.argv) != 2:
    print("Invalid argument number.")
    sys.exit(-1)

try:
    fp = open(sys.argv[1], "rb")
    out = open("../include/gba_bios.h", "w+")
except IOError:
    print("Open file failed.")
with fp:
    out.write("#include <array>\n")
    out.write("#include <cstdint>\n\n")
    out.write("#ifndef CPU_GBA_BIOS_H\n")
    out.write("#define CPU_GBA_BIOS_H\n\n")
    out.write("constexpr static std::array<uint8_t, 16384> biosData {")

    byte = fp.read(1)
    counter = 0
    dataBuffer = ""
    while byte:
        if counter % 32 == 0:
            dataBuffer += "\n\t"
        dataBuffer += '0x{:02x},'.format(byte[0])
        counter += 1
        byte = fp.read(1)
    out.write(dataBuffer[:-1]+"\n};\n\n")
    out.write("#endif // CPU_GBA_BIOS_H\n")
    out.close()
    fp.close()
