from enum import Enum


class v4Type(Enum):
    ALU, PSR, Branch, MUL, MULL, TRANS, MTRANS, SWP, IRT = range(9)


v4ALU = {
    "mov", "movs", "mvn", "mvns", "and", "ands", "eor", "eors",
    "sub", "subs", "rsb", "rsbs", "add", "adds", "adc", "adcs",
    "sbc", "sbcs", "rsc", "rscs", "orr", "orrs", "bic", "bics",
    "cmp", "cmn", "teq", "tst"
}

v4PSR = {
    "mrs", "msr"
}

v4Branch = {
    "b", "bl", "bx"
}

v4MUL = {
    "mul", "mla", "muls", "mlas"
}

v4MULL = {
    "umull", "umlal", "smull", "smlal",
    "umulls", "umlals", "smulls", "smlals"
}

v4Transfer = {
    "ldr", "ldrb", "ldrt", "ldrbt", "ldrh", "ldrsh", "ldrsb",
    "str", "strb", "strt", "strbt", "strh", "strsh", "strsb"
}

v4TransBlock = {
    "ldm", "ldmib", "ldmia", "ldmdb", "ldmda", "stm", "stmib", "stmia",
    "stmdb", "stmda"
}

v4Swp = {
    'swp'
}

v4Interrupt = {
    'svc'
}

v4Shift = {
    "lsl", "lsls", "lsr", "lsrs",
    "asr", "asrs", "ror", "rors"
}
