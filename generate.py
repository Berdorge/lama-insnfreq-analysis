import random
import instructions
import struct
import sys

if len(sys.argv) != 2:
    print("Usage: generate.py <min_file_size>")
    sys.exit(1)

min_file_size = int(sys.argv[1])

instruction_lengths = {
    "add": 0,
    "sub": 0,
    "mul": 0,
    "div": 0,
    "rem": 0,
    "lt": 0,
    "leq": 0,
    "gt": 0,
    "geq": 0,
    "eq": 0,
    "neq": 0,
    "and": 0,
    "or": 0,
    "const": 4,
    "string": 4,
    "sexp": 8,
    "sta": 0,
    "jmp": 4,
    "end": 0,
    "ret": 0,
    "drop": 0,
    "dup": 0,
    "swap": 0,
    "elem": 0,
    "ld_global": 4,
    "ld_local": 4,
    "ld_arg": 4,
    "ld_capture": 4,
    "st_global": 4,
    "st_local": 4,
    "st_arg": 4,
    "st_capture": 4,
    "cjmp_z": 4,
    "cjmp_nz": 4,
    "begin": 8,
    "beginc": 8,
    "closure": 8,
    "callc": 4,
    "call": 8,
    "tag": 8,
    "array": 4,
    "fail": 8,
    "line": 4,
    "pattern_strcmp": 0,
    "pattern_string": 0,
    "pattern_array": 0,
    "pattern_sexp": 0,
    "pattern_boxed": 0,
    "pattern_unboxed": 0,
    "pattern_closure": 0,
    "builtin_read": 0,
    "builtin_write": 0,
    "builtin_length": 0,
    "builtin_string": 0,
    "builtin_array": 4,
    "stop": 0,
}

instruction_mnemonics = list(instruction_lengths.keys())

sys.stdout.buffer.write(struct.pack("i", 0))
sys.stdout.buffer.write(struct.pack("i", 0))
sys.stdout.buffer.write(struct.pack("i", 0))

code = bytearray()
insn_begins = []

while len(code) < min_file_size:
    insn_begins.append(len(code))
    random_insn = random.randint(0, len(instruction_mnemonics) - 1)
    mnemonic = instruction_mnemonics[random_insn]
    code.append(instructions.by_mnemonic[mnemonic][0])
    arg_length = instruction_lengths[mnemonic]
    code.extend(random.randbytes(arg_length))

for begin in insn_begins:
    mnemonic = instructions.by_opcode[code[begin]][0]
    if mnemonic in ["jmp", "cjmp_z", "cjmp_nz", "call", "closure"]:
        target = random.choice(insn_begins)
        struct.pack_into("i", code, begin + 1, target)
    if mnemonic in ["closure"]:
        struct.pack_into("i", code, begin + 5, 0)

sys.stdout.buffer.write(code)
