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

#define ARGLEN_0 return 0;

#define ARGLEN_4 return 4;

#define ARGLEN_8 return 8;

#define ARGLEN_CLOSURE                                                                             \
    uint8_t header[8];                                                                             \
    reader.peek(header, 8);                                                                        \
    uint32_t args_size = le_bytes_to_uint32_t(&header[4]);                                         \
    return 8 + args_size * (1 + 4);

#define NOT_BB_END false

#define IS_BB_END true

#define TARGET_BB_NONE return UINT32_MAX;

#define TARGET_BB_FIRSTARG return reader.peek_uint32_t();

#define INSTRUCTION(NAME, OPCODE, GET_ARGLEN, IS_BB_END, GET_TARGET_BB)                            \
    constexpr uint8_t opcode_##NAME = OPCODE;                                                      \
                                                                                                   \
    struct instruction_##NAME                                                                      \
    {                                                                                              \
        static constexpr uint8_t opcode = opcode_##NAME;                                           \
        static constexpr const char* description = #NAME;                                          \
        static constexpr bool is_bb_end = IS_BB_END;                                               \
                                                                                                   \
        template <typename T>                                                                      \
        static uint32_t get_target_bb(T&& reader)                                                  \
        {                                                                                          \
            GET_TARGET_BB;                                                                         \
        }                                                                                          \
                                                                                                   \
        template <typename T>                                                                      \
        static uint32_t get_args_length(T&& reader)                                                \
        {                                                                                          \
            GET_ARGLEN;                                                                            \
        }                                                                                          \
    };

INSTRUCTION(add, 0x01, ARGLEN_0, NOT_BB_END, TARGET_BB_NONE)
INSTRUCTION(sub, 0x02, ARGLEN_0, NOT_BB_END, TARGET_BB_NONE)
INSTRUCTION(mul, 0x03, ARGLEN_0, NOT_BB_END, TARGET_BB_NONE)
INSTRUCTION(div, 0x04, ARGLEN_0, NOT_BB_END, TARGET_BB_NONE)
INSTRUCTION(rem, 0x05, ARGLEN_0, NOT_BB_END, TARGET_BB_NONE)
INSTRUCTION(lt, 0x06, ARGLEN_0, NOT_BB_END, TARGET_BB_NONE)
INSTRUCTION(leq, 0x07, ARGLEN_0, NOT_BB_END, TARGET_BB_NONE)
INSTRUCTION(gt, 0x08, ARGLEN_0, NOT_BB_END, TARGET_BB_NONE)
INSTRUCTION(geq, 0x09, ARGLEN_0, NOT_BB_END, TARGET_BB_NONE)
INSTRUCTION(eq, 0x0A, ARGLEN_0, NOT_BB_END, TARGET_BB_NONE)
INSTRUCTION(neq, 0x0B, ARGLEN_0, NOT_BB_END, TARGET_BB_NONE)
INSTRUCTION(and, 0x0C, ARGLEN_0, NOT_BB_END, TARGET_BB_NONE)
INSTRUCTION(or, 0x0D, ARGLEN_0, NOT_BB_END, TARGET_BB_NONE)

INSTRUCTION(const, 0x10, ARGLEN_4, NOT_BB_END, TARGET_BB_NONE)
INSTRUCTION(string, 0x11, ARGLEN_4, NOT_BB_END, TARGET_BB_NONE)
INSTRUCTION(sexp, 0x12, ARGLEN_8, NOT_BB_END, TARGET_BB_NONE)
INSTRUCTION(sta, 0x14, ARGLEN_0, NOT_BB_END, TARGET_BB_NONE)
INSTRUCTION(jmp, 0x15, ARGLEN_4, IS_BB_END, TARGET_BB_FIRSTARG)
INSTRUCTION(end, 0x16, ARGLEN_0, IS_BB_END, TARGET_BB_NONE)
INSTRUCTION(ret, 0x17, ARGLEN_0, IS_BB_END, TARGET_BB_NONE)
INSTRUCTION(drop, 0x18, ARGLEN_0, NOT_BB_END, TARGET_BB_NONE)
INSTRUCTION(dup, 0x19, ARGLEN_0, NOT_BB_END, TARGET_BB_NONE)
INSTRUCTION(swap, 0x1A, ARGLEN_0, NOT_BB_END, TARGET_BB_NONE)
INSTRUCTION(elem, 0x1B, ARGLEN_0, NOT_BB_END, TARGET_BB_NONE)

INSTRUCTION(ld_global, 0x20, ARGLEN_4, NOT_BB_END, TARGET_BB_NONE)
INSTRUCTION(ld_local, 0x21, ARGLEN_4, NOT_BB_END, TARGET_BB_NONE)
INSTRUCTION(ld_arg, 0x22, ARGLEN_4, NOT_BB_END, TARGET_BB_NONE)
INSTRUCTION(ld_capture, 0x23, ARGLEN_4, NOT_BB_END, TARGET_BB_NONE)

INSTRUCTION(st_global, 0x40, ARGLEN_4, NOT_BB_END, TARGET_BB_NONE)
INSTRUCTION(st_local, 0x41, ARGLEN_4, NOT_BB_END, TARGET_BB_NONE)
INSTRUCTION(st_arg, 0x42, ARGLEN_4, NOT_BB_END, TARGET_BB_NONE)
INSTRUCTION(st_capture, 0x43, ARGLEN_4, NOT_BB_END, TARGET_BB_NONE)

INSTRUCTION(cjmp_z, 0x50, ARGLEN_4, IS_BB_END, TARGET_BB_FIRSTARG)
INSTRUCTION(cjmp_nz, 0x51, ARGLEN_4, IS_BB_END, TARGET_BB_FIRSTARG)
INSTRUCTION(begin, 0x52, ARGLEN_8, NOT_BB_END, TARGET_BB_NONE)
INSTRUCTION(beginc, 0x53, ARGLEN_8, NOT_BB_END, TARGET_BB_NONE)
INSTRUCTION(closure, 0x54, ARGLEN_CLOSURE, NOT_BB_END, TARGET_BB_FIRSTARG)
INSTRUCTION(callc, 0x55, ARGLEN_4, IS_BB_END, TARGET_BB_NONE)
INSTRUCTION(call, 0x56, ARGLEN_8, IS_BB_END, TARGET_BB_FIRSTARG)
INSTRUCTION(tag, 0x57, ARGLEN_8, NOT_BB_END, TARGET_BB_NONE)
INSTRUCTION(array, 0x58, ARGLEN_4, NOT_BB_END, TARGET_BB_NONE)
INSTRUCTION(fail, 0x59, ARGLEN_8, NOT_BB_END, TARGET_BB_NONE)
INSTRUCTION(line, 0x5A, ARGLEN_4, NOT_BB_END, TARGET_BB_NONE)

INSTRUCTION(pattern_strcmp, 0x60, ARGLEN_0, NOT_BB_END, TARGET_BB_NONE)
INSTRUCTION(pattern_string, 0x61, ARGLEN_0, NOT_BB_END, TARGET_BB_NONE)
INSTRUCTION(pattern_array, 0x62, ARGLEN_0, NOT_BB_END, TARGET_BB_NONE)
INSTRUCTION(pattern_sexp, 0x63, ARGLEN_0, NOT_BB_END, TARGET_BB_NONE)
INSTRUCTION(pattern_boxed, 0x64, ARGLEN_0, NOT_BB_END, TARGET_BB_NONE)
INSTRUCTION(pattern_unboxed, 0x65, ARGLEN_0, NOT_BB_END, TARGET_BB_NONE)
INSTRUCTION(pattern_closure, 0x66, ARGLEN_0, NOT_BB_END, TARGET_BB_NONE)

INSTRUCTION(builtin_read, 0x70, ARGLEN_0, NOT_BB_END, TARGET_BB_NONE)
INSTRUCTION(builtin_write, 0x71, ARGLEN_0, NOT_BB_END, TARGET_BB_NONE)
INSTRUCTION(builtin_length, 0x72, ARGLEN_0, NOT_BB_END, TARGET_BB_NONE)
INSTRUCTION(builtin_string, 0x73, ARGLEN_0, NOT_BB_END, TARGET_BB_NONE)
INSTRUCTION(builtin_array, 0x74, ARGLEN_4, NOT_BB_END, TARGET_BB_NONE)

INSTRUCTION(stop, 0xFF, ARGLEN_0, NOT_BB_END, TARGET_BB_NONE)

using instruction_analyzer = analyzer<
    instruction_add, instruction_sub, instruction_mul, instruction_div, instruction_rem,
    instruction_lt, instruction_leq, instruction_gt, instruction_geq, instruction_eq,
    instruction_neq, instruction_and, instruction_or, instruction_const, instruction_string,
    instruction_sexp, instruction_sta, instruction_jmp, instruction_end, instruction_ret,
    instruction_drop, instruction_dup, instruction_swap, instruction_elem, instruction_ld_global,
    instruction_ld_local, instruction_ld_arg, instruction_ld_capture, instruction_st_global,
    instruction_st_local, instruction_st_arg, instruction_st_capture, instruction_cjmp_z,
    instruction_cjmp_nz, instruction_begin, instruction_beginc, instruction_closure,
    instruction_callc, instruction_call, instruction_tag, instruction_array, instruction_fail,
    instruction_line, instruction_pattern_strcmp, instruction_pattern_string,
    instruction_pattern_array, instruction_pattern_sexp, instruction_pattern_boxed,
    instruction_pattern_unboxed, instruction_pattern_closure, instruction_builtin_array,
    instruction_builtin_read, instruction_builtin_write, instruction_builtin_length,
    instruction_builtin_string, instruction_stop>;

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
        read_file(stdin);
    }
    else
    {
        FILE* f = fopen(input_file, "rb");
        if (f == nullptr)
        {
            failure("Failed to open input file: %s", input_file);
        }
        read_file(f);
        fclose(f);
    }

    std::vector<bool> bb_begins(code_length, false);
    bb_begins[0] = true;

    instruction_analyzer::fill_bb_begins(bb_begins);

    for (uint32_t i = 0; i < public_symbols_number; ++i)
    {
        uint8_t* symbol_ptr = &public_area_ptr[i * 2 * sizeof(uint32_t) + sizeof(uint32_t)];
        uint32_t symbol_offset = le_bytes_to_uint32_t(symbol_ptr);
        bb_begins[symbol_offset] = true;
    }

    hashtable hashtable((code_length / 5 + 256 + code_length / 3 + 65536) / 3 * 4);

    instruction_analyzer::count_occurrences(bb_begins, hashtable);

    instruction_analyzer::print_hashtable(hashtable, output_threshold);
}
