#ifndef ANALYZER_HPP
#define ANALYZER_HPP

#include "assertions.hpp"
#include "bytefile.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <memory>
#include <vector>

constexpr uint32_t hash_initial = 0x811C9DC5;
constexpr uint32_t hash_prime = 0x01000193;
constexpr uint32_t mixing_constant = 0x9E3779B9;

struct reader_t
{
    void peek(uint8_t* buffer, size_t n);
    uint32_t peek_uint32_t();
};

inline void update_hash(uint32_t& hash, uint8_t byte)
{
    hash = (hash ^ byte) * hash_prime;
}

struct hashtable_key
{
    uint32_t ip;
    uint32_t length;

    bool operator==(const hashtable_key& other) const;
};

struct hashtable_entry
{
    hashtable_key key;
    uint32_t value;

    bool operator<(const hashtable_entry& other) const;
};

struct hashtable
{
    uint32_t size;
    std::unique_ptr<hashtable_entry[]> entries;

    hashtable(uint32_t size);

    void mark_occurrence(uint32_t hash, hashtable_key& key);

    uint32_t pack();
};

template <typename... Instructions>
struct analyzer
{
    static char const* opcode_description(uint8_t opcode)
    {
        char const* return_value = "unknown";
        std::initializer_list<int>{
            (opcode == Instructions::opcode ? (return_value = Instructions::description, 0) : 0)...
        };
        return return_value;
    }

    static uint32_t get_args_length(uint8_t opcode)
    {
        uint32_t args_length = 0;
        bool found = false;
        std::initializer_list<int>{
            (opcode == Instructions::opcode
                 ? (args_length = Instructions::get_args_length(reader_t{}), found = true, 0)
                 : 0)...
        };
        if (!found)
        {
            failure("Unknown instruction 0x%02X", opcode);
        }
        return args_length;
    }

    static void fill_bb_begins(std::vector<bool>& bb_begins)
    {
        std::vector<bool> instruction_begins(bb_begins.size(), false);
        fill_instruction_begins(instruction_begins);
        fill_bb_begins(instruction_begins, bb_begins);
    }

    static void fill_instruction_begins(std::vector<bool>& instruction_begins)
    {
        ip = 0;
        while (ip < code_length)
        {
            uint8_t opcode = next_code_byte();
            bool found = false;
            std::initializer_list<int>{
                (opcode == Instructions::opcode
                     ? (instruction_begins[ip - 1] = found = true,
                        ip += Instructions::get_args_length(reader_t{}), 0)
                     : 0)...
            };
            if (!found)
            {
                failure("Unknown instruction 0x%02X at offset %zu", opcode, ip - 1);
            }
        }
    }

    static void
    fill_bb_begins(std::vector<bool> const& instruction_begins, std::vector<bool>& bb_begins)
    {
        bool is_bb_end = false;
        ip = 0;
        while (ip < code_length)
        {
            if (!instruction_begins[ip])
            {
                ++ip;
                continue;
            }
            if (is_bb_end)
            {
                bb_begins[ip] = true;
                is_bb_end = false;
            }
            uint32_t instruction_begin = ip;
            uint32_t target_bb = UINT32_MAX;
            uint8_t opcode = next_code_byte();
            std::initializer_list<int>{
                (opcode == Instructions::opcode
                     ? (is_bb_end = Instructions::is_bb_end,
                        target_bb = Instructions::get_target_bb(reader_t{}), 0)
                     : 0)...
            };
            if (target_bb != UINT32_MAX)
            {
                if (target_bb >= instruction_begins.size() || !instruction_begins[target_bb])
                {
                    failure(
                        "Jump target 0x%08X at offset %zu is not an instruction start", target_bb,
                        instruction_begin
                    );
                }
                bb_begins[target_bb] = true;
            }
        }
    }

    static void count_occurrences(std::vector<bool> const& bb_begins, hashtable& hashtable)
    {
        uint32_t hash = hash_initial;
        hashtable_key key;

        for (ip = 0; ip < code_length;)
        {
            hashtable_key prev_key;
            prev_key.ip = key.ip;
            uint32_t prev_hash = hash;

            key.ip = ip;
            hash = hash_initial;

            uint8_t opcode = next_code_byte();
            update_hash(prev_hash, opcode);
            update_hash(hash, opcode);

            uint32_t args_length = get_args_length(opcode);
            for (uint32_t i = 0; i < args_length; i++)
            {
                uint8_t byte = next_code_byte();
                update_hash(prev_hash, byte);
                update_hash(hash, byte);
            }

            hashtable.mark_occurrence(hash, key);

            if (!bb_begins[key.ip])
            {
                hashtable.mark_occurrence(prev_hash, prev_key);
            }
        }
    }

    static void print_hashtable(hashtable& table, uint32_t threshold)
    {
        uint32_t packed_size = table.pack();
        std::sort(table.entries.get(), table.entries.get() + packed_size);

        uint32_t i;
        for (i = 0; i < packed_size && table.entries[i].value < threshold; ++i)
            ;
        for (; i < packed_size; ++i)
        {
            hashtable_entry& entry = table.entries[i];
            printf("%u x", entry.value);
            for (ip = entry.key.ip; ip < entry.key.ip + entry.key.length;)
            {
                uint8_t opcode = next_code_byte();
                printf(" %s", opcode_description(opcode));
                uint32_t args_length = get_args_length(opcode);
                for (uint32_t j = 0; j < args_length; ++j)
                {
                    uint8_t byte = next_code_byte();
                    printf(" %02X", byte);
                }
            }
            printf("\n");
        }
    }
};

#endif
