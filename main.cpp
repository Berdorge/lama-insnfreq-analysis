#include "analyzer.hpp"
#include "assertions.hpp"
#include "bytefile.hpp"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <iomanip>
#include <memory>
#include <optional>
#include <random>
#include <set>
#include <sstream>
#include <string>
#include <tuple>
#include <unordered_map>
#include <vector>

#define INSTRUCTION(name, opcode, print)                                                           \
    constexpr uint8_t opcode_##name = opcode;                                                      \
                                                                                                   \
    void print_##name(reader_t& reader, FILE* file)                                                \
    {                                                                                              \
        print                                                                                      \
    }

#define PRINT_NOARG(description) file == nullptr ? 0 : fprintf(file, "%s", description);

#define PRINT_1ARG(description)                                                                    \
    uint32_t arg1 = reader.next_code_uint32_t();                                                   \
    file == nullptr ? 0 : fprintf(file, "%s %u", description, arg1);

#define PRINT_2ARG(description)                                                                    \
    uint32_t arg1 = reader.next_code_uint32_t();                                                   \
    uint32_t arg2 = reader.next_code_uint32_t();                                                   \
    file == nullptr ? 0 : fprintf(file, "%s %u %u", description, arg1, arg2);

#define PRINT_CLOSURE                                                                              \
    uint32_t target = reader.next_code_uint32_t();                                                 \
    uint32_t args_size = reader.next_code_uint32_t();                                              \
    file == nullptr ? 0 : fprintf(file, "CLOSURE %u %u", target, args_size);                       \
    for (uint32_t i = 0; i < args_size; ++i)                                                       \
    {                                                                                              \
        uint8_t designation = reader.next_code_byte();                                             \
        uint32_t index = reader.next_code_uint32_t();                                              \
        file == nullptr ? 0 : fprintf(file, " %u %u", designation, index);                         \
    }

INSTRUCTION(add, 0x01, PRINT_NOARG("ADD"))
INSTRUCTION(sub, 0x02, PRINT_NOARG("SUB"))
INSTRUCTION(mul, 0x03, PRINT_NOARG("MUL"))
INSTRUCTION(div, 0x04, PRINT_NOARG("DIV"))
INSTRUCTION(rem, 0x05, PRINT_NOARG("REM"))
INSTRUCTION(lt, 0x06, PRINT_NOARG("LT"))
INSTRUCTION(leq, 0x07, PRINT_NOARG("LEQ"))
INSTRUCTION(gt, 0x08, PRINT_NOARG("GT"))
INSTRUCTION(geq, 0x09, PRINT_NOARG("GEQ"))
INSTRUCTION(eq, 0x0A, PRINT_NOARG("EQ"))
INSTRUCTION(neq, 0x0B, PRINT_NOARG("NEQ"))
INSTRUCTION(and, 0x0C, PRINT_NOARG("AND"))
INSTRUCTION(or, 0x0D, PRINT_NOARG("OR"))

INSTRUCTION(const, 0x10, PRINT_1ARG("CONST"))
INSTRUCTION(string, 0x11, PRINT_1ARG("STRING"))
INSTRUCTION(sexp, 0x12, PRINT_2ARG("SEXP"))
INSTRUCTION(sta, 0x14, PRINT_NOARG("STA"))
INSTRUCTION(jmp, 0x15, PRINT_1ARG("JMP"))
INSTRUCTION(end, 0x16, PRINT_NOARG("END"))
INSTRUCTION(ret, 0x17, PRINT_NOARG("RET"))
INSTRUCTION(drop, 0x18, PRINT_NOARG("DROP"))
INSTRUCTION(dup, 0x19, PRINT_NOARG("DUP"))
INSTRUCTION(swap, 0x1A, PRINT_NOARG("SWAP"))
INSTRUCTION(elem, 0x1B, PRINT_NOARG("ELEM"))

INSTRUCTION(ld_global, 0x20, PRINT_1ARG("LD_GLOBAL"))
INSTRUCTION(ld_local, 0x21, PRINT_1ARG("LD_LOCAL"))
INSTRUCTION(ld_arg, 0x22, PRINT_1ARG("LD_ARG"))
INSTRUCTION(ld_capture, 0x23, PRINT_1ARG("LD_CAPTURE"))

INSTRUCTION(st_global, 0x40, PRINT_1ARG("ST_GLOBAL"))
INSTRUCTION(st_local, 0x41, PRINT_1ARG("ST_LOCAL"))
INSTRUCTION(st_arg, 0x42, PRINT_1ARG("ST_ARG"))
INSTRUCTION(st_capture, 0x43, PRINT_1ARG("ST_CAPTURE"))

INSTRUCTION(cjmp_z, 0x50, PRINT_1ARG("CJMP_Z"))
INSTRUCTION(cjmp_nz, 0x51, PRINT_1ARG("CJMP_NZ"))
INSTRUCTION(begin, 0x52, PRINT_2ARG("BEGIN"))
INSTRUCTION(beginc, 0x53, PRINT_2ARG("BEGINC"))
INSTRUCTION(closure, 0x54, PRINT_CLOSURE)
INSTRUCTION(callc, 0x55, PRINT_1ARG("CALLC"))
INSTRUCTION(call, 0x56, PRINT_2ARG("CALL"))
INSTRUCTION(tag, 0x57, PRINT_2ARG("TAG"))
INSTRUCTION(array, 0x58, PRINT_1ARG("ARRAY"))
INSTRUCTION(fail, 0x59, PRINT_2ARG("FAIL"))
INSTRUCTION(line, 0x5A, PRINT_1ARG("LINE"))

INSTRUCTION(pattern_strcmp, 0x60, PRINT_NOARG("PATTERN_STRCMP"))
INSTRUCTION(pattern_string, 0x61, PRINT_NOARG("PATTERN_STRING"))
INSTRUCTION(pattern_array, 0x62, PRINT_NOARG("PATTERN_ARRAY"))
INSTRUCTION(pattern_sexp, 0x63, PRINT_NOARG("PATTERN_SEXP"))
INSTRUCTION(pattern_boxed, 0x64, PRINT_NOARG("PATTERN_BOXED"))
INSTRUCTION(pattern_unboxed, 0x65, PRINT_NOARG("PATTERN_UNBOXED"))
INSTRUCTION(pattern_closure, 0x66, PRINT_NOARG("PATTERN_CLOSURE"))

INSTRUCTION(builtin_read, 0x70, PRINT_NOARG("BUILTIN_READ"))
INSTRUCTION(builtin_write, 0x71, PRINT_NOARG("BUILTIN_WRITE"))
INSTRUCTION(builtin_length, 0x72, PRINT_NOARG("BUILTIN_LENGTH"))
INSTRUCTION(builtin_string, 0x73, PRINT_NOARG("BUILTIN_STRING"))
INSTRUCTION(builtin_array, 0x74, PRINT_1ARG("BUILTIN_ARRAY"))

struct handler
{
    instruction_result describe_flow(reader_t& reader)
    {
        instruction_result result;
        result.target = UINT32_MAX;
        result.flow = instruction_flow::normal;

        uint32_t initial_ip = reader.ip;
        uint8_t opcode = reader.next_code_byte();

        switch (opcode)
        {
        case opcode_jmp:
        case opcode_end:
        case opcode_ret:
        case opcode_fail:
            result.flow = instruction_flow::stop;
            break;

        case opcode_cjmp_z:
        case opcode_cjmp_nz:
        case opcode_call:
        case opcode_callc:
            result.flow = instruction_flow::call;
            break;
        }

        switch (opcode)
        {
        case opcode_jmp:
        case opcode_cjmp_z:
        case opcode_cjmp_nz:
        case opcode_call:
        case opcode_closure:
            result.target = reader.next_code_uint32_t();
            break;
        }

        reader.ip = initial_ip;
        return result;
    }

    void print(reader_t& reader, FILE* file)
    {
#define CASE(name)                                                                                 \
    case opcode_##name:                                                                            \
        print_##name(reader, file);                                                                \
        break;

        uint8_t opcode = reader.next_code_byte();

        switch (opcode)
        {
            CASE(add)
            CASE(sub)
            CASE(mul)
            CASE(div)
            CASE(rem)
            CASE(lt)
            CASE(leq)
            CASE(gt)
            CASE(geq)
            CASE(eq)
            CASE(neq)
            CASE(and)
            CASE(or)
            CASE(const)
            CASE(string)
            CASE(sexp)
            CASE(sta)
            CASE(jmp)
            CASE(end)
            CASE(ret)
            CASE(drop)
            CASE(dup)
            CASE(swap)
            CASE(elem)
            CASE(ld_global)
            CASE(ld_local)
            CASE(ld_arg)
            CASE(ld_capture)
            CASE(st_global)
            CASE(st_local)
            CASE(st_arg)
            CASE(st_capture)
            CASE(cjmp_z)
            CASE(cjmp_nz)
            CASE(begin)
            CASE(beginc)
            CASE(closure)
            CASE(callc)
            CASE(call)
            CASE(tag)
            CASE(array)
            CASE(fail)
            CASE(line)
            CASE(pattern_strcmp)
            CASE(pattern_string)
            CASE(pattern_array)
            CASE(pattern_sexp)
            CASE(pattern_boxed)
            CASE(pattern_unboxed)
            CASE(pattern_closure)
            CASE(builtin_read)
            CASE(builtin_write)
            CASE(builtin_length)
            CASE(builtin_string)
            CASE(builtin_array)
        default:
            failure("Unknown instruction 0x%02X at offset %zu", opcode, reader.ip - 1);
            break;
        }
    }
};

int main(int argc, char* argv[])
{
    uint32_t output_threshold = 1;
    char* input_file = nullptr;

    for (int i = 1; i < argc;)
    {
        std::string arg = argv[i];
        if (arg == "--threshold")
        {
            output_threshold = std::stoul(argv[i + 1]);
            i += 2;
        }
        else if (arg == "--input")
        {
            input_file = argv[i + 1];
            i += 2;
        }
        else
        {
            failure("Unknown argument: %s", argv[i]);
        }
    }

    if (input_file == nullptr)
    {
        failure("--input file not specified");
    }

    FILE* f = fopen(input_file, "rb");
    if (f == nullptr)
    {
        failure("Failed to open input file: %s", input_file);
    }
    bytefile bf = read_file(f);
    fclose(f);

    uint32_t max_entries = bf.code_length / 5 + 256 + bf.code_length / 3 + 65536;
    analyzer<handler> analyzer(bf.code_ptr, bf.code_length, max_entries);

    for (uint32_t i = 0; i < bf.public_symbols_number; ++i)
    {
        uint8_t* symbol_ptr = &bf.public_area_ptr[i * 2 * sizeof(uint32_t) + sizeof(uint32_t)];
        uint32_t symbol_offset = le_bytes_to_uint32_t(symbol_ptr);
        analyzer.find_reachable(symbol_offset);
    }

    analyzer.count_occurrences();
    analyzer.print_hashtable(output_threshold);
}
