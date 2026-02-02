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

constexpr uint8_t opcode_add = 0x01;
constexpr uint8_t opcode_sub = 0x02;
constexpr uint8_t opcode_mul = 0x03;
constexpr uint8_t opcode_div = 0x04;
constexpr uint8_t opcode_rem = 0x05;
constexpr uint8_t opcode_lt = 0x06;
constexpr uint8_t opcode_leq = 0x07;
constexpr uint8_t opcode_gt = 0x08;
constexpr uint8_t opcode_geq = 0x09;
constexpr uint8_t opcode_eq = 0x0A;
constexpr uint8_t opcode_neq = 0x0B;
constexpr uint8_t opcode_and = 0x0C;
constexpr uint8_t opcode_or = 0x0D;

constexpr uint8_t opcode_const = 0x10;
constexpr uint8_t opcode_string = 0x11;
constexpr uint8_t opcode_sexp = 0x12;
constexpr uint8_t opcode_sta = 0x14;
constexpr uint8_t opcode_jmp = 0x15;
constexpr uint8_t opcode_end = 0x16;
constexpr uint8_t opcode_ret = 0x17;
constexpr uint8_t opcode_drop = 0x18;
constexpr uint8_t opcode_dup = 0x19;
constexpr uint8_t opcode_swap = 0x1A;
constexpr uint8_t opcode_elem = 0x1B;

constexpr uint8_t designation_global = 0x00;
constexpr uint8_t designation_local = 0x01;
constexpr uint8_t designation_arg = 0x02;
constexpr uint8_t designation_capture = 0x03;

constexpr uint8_t opcode_ld_base = 0x20;
constexpr uint8_t opcode_ld_global = opcode_ld_base + designation_global;
constexpr uint8_t opcode_ld_local = opcode_ld_base + designation_local;
constexpr uint8_t opcode_ld_arg = opcode_ld_base + designation_arg;
constexpr uint8_t opcode_ld_capture = opcode_ld_base + designation_capture;

constexpr uint8_t opcode_st_base = 0x40;
constexpr uint8_t opcode_st_global = opcode_st_base + designation_global;
constexpr uint8_t opcode_st_local = opcode_st_base + designation_local;
constexpr uint8_t opcode_st_arg = opcode_st_base + designation_arg;
constexpr uint8_t opcode_st_capture = opcode_st_base + designation_capture;

constexpr uint8_t opcode_cjmp_z = 0x50;
constexpr uint8_t opcode_cjmp_nz = 0x51;
constexpr uint8_t opcode_begin = 0x52;
constexpr uint8_t opcode_beginc = 0x53;
constexpr uint8_t opcode_closure = 0x54;
constexpr uint8_t opcode_callc = 0x55;
constexpr uint8_t opcode_call = 0x56;
constexpr uint8_t opcode_tag = 0x57;
constexpr uint8_t opcode_array = 0x58;
constexpr uint8_t opcode_fail = 0x59;
constexpr uint8_t opcode_line = 0x5A;

constexpr uint8_t opcode_pattern_strcmp = 0x60;
constexpr uint8_t opcode_pattern_string = 0x61;
constexpr uint8_t opcode_pattern_array = 0x62;
constexpr uint8_t opcode_pattern_sexp = 0x63;
constexpr uint8_t opcode_pattern_boxed = 0x64;
constexpr uint8_t opcode_pattern_unboxed = 0x65;
constexpr uint8_t opcode_pattern_closure = 0x66;

constexpr uint8_t opcode_builtin_read = 0x70;
constexpr uint8_t opcode_builtin_write = 0x71;
constexpr uint8_t opcode_builtin_length = 0x72;
constexpr uint8_t opcode_builtin_string = 0x73;
constexpr uint8_t opcode_builtin_array = 0x74;

static char const* opcode_description(uint8_t opcode)
{
    switch (opcode)
    {
    case opcode_add:
        return "ADD";
    case opcode_sub:
        return "SUB";
    case opcode_mul:
        return "MUL";
    case opcode_div:
        return "DIV";
    case opcode_rem:
        return "REM";
    case opcode_lt:
        return "LT";
    case opcode_leq:
        return "LEQ";
    case opcode_gt:
        return "GT";
    case opcode_geq:
        return "GEQ";
    case opcode_eq:
        return "EQ";
    case opcode_neq:
        return "NEQ";
    case opcode_and:
        return "AND";
    case opcode_or:
        return "OR";

    case opcode_const:
        return "CONST";
    case opcode_string:
        return "STRING";
    case opcode_sexp:
        return "SEXP";
    case opcode_sta:
        return "STA";
    case opcode_jmp:
        return "JMP";
    case opcode_end:
        return "END";
    case opcode_ret:
        return "RET";
    case opcode_drop:
        return "DROP";
    case opcode_dup:
        return "DUP";
    case opcode_swap:
        return "SWAP";
    case opcode_elem:
        return "ELEM";

    case opcode_ld_global:
        return "LD_GLOBAL";
    case opcode_ld_local:
        return "LD_LOCAL";
    case opcode_ld_arg:
        return "LD_ARG";
    case opcode_ld_capture:
        return "LD_CAPTURE";

    case opcode_st_global:
        return "ST_GLOBAL";
    case opcode_st_local:
        return "ST_LOCAL";
    case opcode_st_arg:
        return "ST_ARG";
    case opcode_st_capture:
        return "ST_CAPTURE";

    case opcode_cjmp_z:
        return "CJMP_Z";
    case opcode_cjmp_nz:
        return "CJMP_NZ";
    case opcode_begin:
        return "BEGIN";
    case opcode_beginc:
        return "BEGINC";
    case opcode_closure:
        return "CLOSURE";
    case opcode_callc:
        return "CALLC";
    case opcode_call:
        return "CALL";
    case opcode_tag:
        return "TAG";
    case opcode_array:
        return "ARRAY";
    case opcode_fail:
        return "FAIL";
    case opcode_line:
        return "LINE";

    case opcode_pattern_strcmp:
        return "PATTERN_STRCMP";
    case opcode_pattern_string:
        return "PATTERN_STRING";
    case opcode_pattern_array:
        return "PATTERN_ARRAY";
    case opcode_pattern_sexp:
        return "PATTERN_SEXP";
    case opcode_pattern_boxed:
        return "PATTERN_BOXED";
    case opcode_pattern_unboxed:
        return "PATTERN_UNBOXED";
    case opcode_pattern_closure:
        return "PATTERN_CLOSURE";

    case opcode_builtin_read:
        return "BUILTIN_READ";
    case opcode_builtin_write:
        return "BUILTIN_WRITE";
    case opcode_builtin_length:
        return "BUILTIN_LENGTH";
    case opcode_builtin_string:
        return "BUILTIN_STRING";
    case opcode_builtin_array:
        return "BUILTIN_ARRAY";

    default:
        return "UNKNOWN";
    }
}

struct handler
{
    instruction_result interpret(reader_t& reader)
    {
        instruction_result result;
        result.target = UINT32_MAX;
        result.flow = instruction_flow::normal;

        uint8_t opcode = reader.next_code_byte();
        switch (opcode)
        {
        case opcode_add:
        case opcode_sub:
        case opcode_mul:
        case opcode_div:
        case opcode_rem:
        case opcode_lt:
        case opcode_leq:
        case opcode_gt:
        case opcode_geq:
        case opcode_eq:
        case opcode_neq:
        case opcode_and:
        case opcode_or:
        case opcode_sta:
        case opcode_drop:
        case opcode_dup:
        case opcode_swap:
        case opcode_elem:
        case opcode_pattern_strcmp:
        case opcode_pattern_string:
        case opcode_pattern_array:
        case opcode_pattern_sexp:
        case opcode_pattern_boxed:
        case opcode_pattern_unboxed:
        case opcode_pattern_closure:
        case opcode_builtin_read:
        case opcode_builtin_write:
        case opcode_builtin_length:
        case opcode_builtin_string:
            break;

        case opcode_const:
        case opcode_string:
        case opcode_ld_global:
        case opcode_ld_local:
        case opcode_ld_arg:
        case opcode_ld_capture:
        case opcode_st_global:
        case opcode_st_local:
        case opcode_st_arg:
        case opcode_st_capture:
        case opcode_array:
        case opcode_line:
        case opcode_builtin_array:
            reader.next_code_uint32_t();
            break;

        case opcode_sexp:
        case opcode_begin:
        case opcode_beginc:
        case opcode_tag:
            reader.next_code_uint32_t();
            reader.next_code_uint32_t();
            break;

        case opcode_jmp:
            result.target = reader.next_code_uint32_t();
            result.flow = instruction_flow::stop;
            break;

        case opcode_end:
        case opcode_ret:
            result.flow = instruction_flow::stop;
            break;

        case opcode_cjmp_z:
        case opcode_cjmp_nz:
            result.target = reader.next_code_uint32_t();
            result.flow = instruction_flow::call;
            break;

        case opcode_closure:
        {
            result.target = reader.next_code_uint32_t();
            uint32_t args_size = reader.next_code_uint32_t();
            for (uint32_t i = 0; i < args_size; ++i)
            {
                reader.next_code_byte();
                reader.next_code_uint32_t();
            }
            break;
        }

        case opcode_callc:
            reader.next_code_uint32_t();
            result.flow = instruction_flow::call;
            break;

        case opcode_call:
            result.target = reader.next_code_uint32_t();
            reader.next_code_uint32_t();
            result.flow = instruction_flow::call;
            break;

        case opcode_fail:
            reader.next_code_uint32_t();
            reader.next_code_uint32_t();
            result.flow = instruction_flow::stop;
            break;

        default:
            failure("Unknown instruction 0x%02X at offset %zu", opcode, reader.ip - 1);
            break;
        }

        return result;
    }

    void print(reader_t& reader)
    {
        uint8_t opcode = reader.next_code_byte();
        uint32_t args_begin = reader.ip;
        reader.ip -= 1;

        printf(" %s", opcode_description(opcode));
        interpret(reader);
        uint32_t args_length = reader.ip - args_begin;
        reader.ip = args_begin;
        for (uint32_t i = 0; i < args_length; ++i)
        {
            uint8_t byte = reader.next_code_byte();
            printf(" %02X", byte);
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
        analyzer.visit(symbol_offset);
    }

    analyzer.print_hashtable(output_threshold);
}
