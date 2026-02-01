import sys
import os
import subprocess
import struct
import instructions


def test_file(file):
    print(f"Testing file: {file}")

    bb_begins = set([0])
    with open(file, "rb") as f:
        stringtab_size = struct.unpack("i", f.read(4))[0]
        global_area_size = struct.unpack("i", f.read(4))[0]
        public_symbols_number = struct.unpack("i", f.read(4))[0]
        for _ in range(public_symbols_number):
            f.read(4)
            bb_begin = struct.unpack("i", f.read(4))[0]
            bb_begins.add(bb_begin)
        f.read(stringtab_size)
        code = f.read()

    ip = 0
    is_bb_end = False
    while ip < len(code):
        if is_bb_end:
            bb_begins.add(ip)
            is_bb_end = False
        opcode = code[ip]
        ip += 1
        if opcode in [instructions.by_mnemonic["closure"][0]]:
            target = struct.unpack("i", code[ip : ip + 4])[0]
            bb_begins.add(target)
        if opcode in [
            instructions.by_mnemonic["jmp"][0],
            instructions.by_mnemonic["cjmp_z"][0],
            instructions.by_mnemonic["cjmp_nz"][0],
            instructions.by_mnemonic["call"][0],
        ]:
            target = struct.unpack("i", code[ip : ip + 4])[0]
            bb_begins.add(target)
            is_bb_end = True
        if opcode in [
            instructions.by_mnemonic["end"][0],
            instructions.by_mnemonic["ret"][0],
            instructions.by_mnemonic["callc"][0],
        ]:
            is_bb_end = True
        _, reader = instructions.by_opcode[opcode]
        args = reader(code, ip)
        ip += len(args)

    occurrences = {}
    insn_bytes = None
    ip = 0
    while ip < len(code):
        prev_insn_bytes = insn_bytes
        opcode = code[ip]
        ip += 1
        _, reader = instructions.by_opcode[opcode]
        insn = []
        insn.append(opcode)
        insn.extend(reader(code, ip))
        ip += len(insn) - 1
        insn_bytes = bytes(insn)
        occurrences[insn_bytes] = occurrences.get(insn_bytes, 0) + 1
        if (ip - len(insn)) not in bb_begins:
            consecutive = prev_insn_bytes + insn_bytes
            occurrences[consecutive] = occurrences.get(consecutive, 0) + 1

    process = subprocess.Popen(
        ["build/lama-insnfreq-analysis", "--input", file, "--threshold", "1"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    actual_output, stderr = process.communicate()
    for line in actual_output.splitlines():
        parts = line.split()
        actual_occurrences = int(parts.pop(0))
        parts.pop(0)
        insn = []
        for i in range(len(parts)):
            if parts[i] in instructions.by_mnemonic:
                insn.append(instructions.by_mnemonic[parts[i]][0])
            else:
                insn.append(int(parts[i], 16))
        insn_bytes = bytes(insn)
        if insn_bytes not in occurrences:
            print(f"Excess instruction: {line}")
            return True
        if occurrences[insn_bytes] != actual_occurrences:
            print(
                f"Expected {occurrences[insn_bytes]} occurrences, got {actual_occurrences}: {line}"
            )
            return True
        del occurrences[insn_bytes]
    if occurrences:
        for insn, count in occurrences.items():
            insn_str = " ".join(f"{byte:02X}" for byte in insn)
            print(f"Missing ({count} occurrences): {insn_str}")
        return True

    return False


test_files = [
    dir + "/" + f
    for dir in [
        "Lama/performance",
        "Lama/regression",
        "Lama/regression_long/expressions",
        "Lama/regression_long/deep-expressions",
    ]
    for f in os.listdir(dir)
    if f.endswith(".bc")
]

for filename in sorted(test_files):
    if test_file(filename):
        sys.exit(1)
