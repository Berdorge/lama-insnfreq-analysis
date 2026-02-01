def read_none(code, i):
    return []


def read_4(code, i):
    return [code[j] for j in range(i, i + 4)]


def read_8(code, i):
    return [code[j] for j in range(i, i + 8)]


def read_closure(code, i):
    result = [code[j] for j in range(i, i + 8)]
    num_captures = int.from_bytes(result[4:8], byteorder="little")
    i += 8
    for _ in range(num_captures):
        result.extend([code[j] for j in range(i, i + 5)])
        i += 5
    return result


by_mnemonic = {
    "add": (0x01, read_none),
    "sub": (0x02, read_none),
    "mul": (0x03, read_none),
    "div": (0x04, read_none),
    "rem": (0x05, read_none),
    "lt": (0x06, read_none),
    "leq": (0x07, read_none),
    "gt": (0x08, read_none),
    "geq": (0x09, read_none),
    "eq": (0x0A, read_none),
    "neq": (0x0B, read_none),
    "and": (0x0C, read_none),
    "or": (0x0D, read_none),
    "const": (0x10, read_4),
    "string": (0x11, read_4),
    "sexp": (0x12, read_8),
    "sta": (0x14, read_none),
    "jmp": (0x15, read_4),
    "end": (0x16, read_none),
    "ret": (0x17, read_none),
    "drop": (0x18, read_none),
    "dup": (0x19, read_none),
    "swap": (0x1A, read_none),
    "elem": (0x1B, read_none),
    "ld_global": (0x20, read_4),
    "ld_local": (0x21, read_4),
    "ld_arg": (0x22, read_4),
    "ld_capture": (0x23, read_4),
    "st_global": (0x40, read_4),
    "st_local": (0x41, read_4),
    "st_arg": (0x42, read_4),
    "st_capture": (0x43, read_4),
    "cjmp_z": (0x50, read_4),
    "cjmp_nz": (0x51, read_4),
    "begin": (0x52, read_8),
    "beginc": (0x53, read_8),
    "closure": (0x54, read_closure),
    "callc": (0x55, read_4),
    "call": (0x56, read_8),
    "tag": (0x57, read_8),
    "array": (0x58, read_4),
    "fail": (0x59, read_8),
    "line": (0x5A, read_4),
    "pattern_strcmp": (0x60, read_none),
    "pattern_string": (0x61, read_none),
    "pattern_array": (0x62, read_none),
    "pattern_sexp": (0x63, read_none),
    "pattern_boxed": (0x64, read_none),
    "pattern_unboxed": (0x65, read_none),
    "pattern_closure": (0x66, read_none),
    "builtin_read": (0x70, read_none),
    "builtin_write": (0x71, read_none),
    "builtin_length": (0x72, read_none),
    "builtin_string": (0x73, read_none),
    "builtin_array": (0x74, read_4),
    "stop": (0xFF, read_none),
}

by_opcode = {v[0]: (k, v[1]) for k, v in by_mnemonic.items()}
