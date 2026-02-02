import sys
import os
import subprocess
import struct
import instructions


def test_file(file):
    print(f"Testing file: {file}")

    worklist = []
    with open(file, "rb") as f:
        stringtab_size = struct.unpack("i", f.read(4))[0]
        global_area_size = struct.unpack("i", f.read(4))[0]
        public_symbols_number = struct.unpack("i", f.read(4))[0]
        for _ in range(public_symbols_number):
            f.read(4)
            public_ptr = struct.unpack("i", f.read(4))[0]
            worklist.append(public_ptr)
        f.read(stringtab_size)
        code = f.read()

    occurrences = {}
    visited = set()
    while worklist:
        ip = worklist.pop()

        insn = []
        while True:
            if ip in visited:
                break
            visited.add(ip)
            prev_insn = insn

            opcode = code[ip]
            insn = [opcode]
            _, reader = instructions.by_opcode[opcode]

            args, is_break = reader(code, ip + 1, worklist)
            insn.extend(args)
            ip += len(insn)

            insn_bytes = bytes(insn)
            occurrences[insn_bytes] = occurrences.get(insn_bytes, 0) + 1
            if prev_insn:
                consecutive = bytes(prev_insn) + insn_bytes
                occurrences[consecutive] = occurrences.get(consecutive, 0) + 1

            if is_break:
                break

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
