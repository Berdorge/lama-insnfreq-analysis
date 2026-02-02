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

inline void update_hash(uint32_t& hash, uint8_t byte)
{
    hash = (hash ^ byte) * hash_prime;
}

struct reader_t
{
    uint8_t* code;
    uint32_t code_length;
    uint32_t ip;
    uint32_t hash1;
    uint32_t hash2;

    void check_code_has(size_t n, char const* what)
    {
        if (ip + n > code_length)
        {
            failure("Expected %s at offset %zu, got end of bytecode", what, ip);
        }
    }

    uint8_t next_code_byte()
    {
        uint8_t value;
        read(&value, 1, "byte");
        return value;
    }

    uint32_t next_code_uint32_t()
    {
        uint8_t buffer[4];
        read(buffer, 4, "4-byte int");
        uint32_t value = le_bytes_to_uint32_t(buffer);
        return value;
    }

    void read(uint8_t* buffer, size_t n, char const* what)
    {
        check_code_has(n, what);
        for (size_t i = 0; i < n; ++i)
        {
            uint8_t byte = code[ip + i];
            buffer[i] = byte;
            update_hash(hash1, byte);
            update_hash(hash2, byte);
        }
        ip += n;
    }
};

enum class instruction_flow
{
    /**
     * Only the next instruction is directly reachable.
     *
     * This is the only flow that allows the current instruction
     * to be considered as a beginning of a two-instruction sequence.
     */
    normal,

    /**
     * Both the next instruction and the target are directly reachable.
     *
     * The current instruction is not considered
     * as a beginning of a two-instruction sequence.
     *
     * Note that this flow, despite its name,
     * is also intended to be used for conditional jumps.
     */
    call,

    /**
     * The next instruction is not directly reachable.
     * Naturally, the current instruction is not considered
     * as a beginning of a two-instruction sequence.
     *
     * If the target is specified, it is considered directly reachable.
     * For example, this is intended to be used for unconditional jumps.
     */
    stop
};

struct instruction_result
{
    /**
     * UINT32_MAX means "no target".
     */
    uint32_t target;

    instruction_flow flow;
};

struct hashtable_key
{
    uint32_t ip;
    uint32_t length;
};

struct hashtable_entry
{
    hashtable_key key;
    uint32_t value;

    bool operator<(const hashtable_entry& other) const
    {
        return value < other.value;
    }
};

struct hashtable
{
    uint32_t size;
    std::unique_ptr<hashtable_entry[]> entries;

    hashtable(uint32_t size);

    void mark_occurrence(uint8_t* code_ptr, uint32_t hash, uint32_t ip, uint32_t length);

    uint32_t pack();
};

template <typename Handler>
struct analyzer
{
    uint8_t* code_ptr;
    uint32_t code_size;
    std::vector<bool> visited;
    hashtable table;

    analyzer(uint8_t* code_ptr, uint32_t code_size, uint32_t max_entries)
        : code_ptr(code_ptr), code_size(code_size), visited(code_size, false),
          table(max_entries / 3 * 4)
    {
    }

    void visit(uint32_t ip)
    {
        std::vector worklist{ip};

        while (!worklist.empty())
        {
            uint32_t ip = worklist.back();
            worklist.pop_back();
            reader_t reader = make_reader(ip);
            reader.hash1 = hash_initial;

            for (uint32_t i = 0;; ++i)
            {
                uint32_t prev_ip = ip;
                ip = reader.ip;

                if (visited[ip])
                {
                    break;
                }
                visited[ip] = true;

                reader.hash2 = reader.hash1;
                reader.hash1 = hash_initial;

                instruction_result result = Handler().interpret(reader);

                table.mark_occurrence(code_ptr, reader.hash1, ip, reader.ip - ip);
                if (i)
                {
                    table.mark_occurrence(code_ptr, reader.hash2, prev_ip, reader.ip - prev_ip);
                }

                if (result.target != UINT32_MAX)
                {
                    worklist.push_back(result.target);
                }
                if (result.flow != instruction_flow::normal)
                {
                    if (result.flow == instruction_flow::call && reader.ip < code_size)
                    {
                        worklist.push_back(reader.ip);
                    }
                    break;
                }
            }
        }
    }

    void print_hashtable(uint32_t threshold)
    {
        uint32_t packed_size = table.pack();
        std::sort(table.entries.get(), table.entries.get() + packed_size);

        uint32_t i;
        for (i = 0; i < packed_size && table.entries[i].value < threshold; ++i)
            ;
        for (; i < packed_size; ++i)
        {
            hashtable_entry& entry = table.entries[i];
            reader_t reader = make_reader(entry.key.ip);
            printf("%u x", entry.value);
            while (reader.ip < entry.key.ip + entry.key.length)
            {
                Handler().print(reader);
            }
            printf("\n");
        }
    }

  private:
    reader_t make_reader(uint32_t ip)
    {
        reader_t reader;
        reader.code = code_ptr;
        reader.code_length = code_size;
        reader.ip = ip;
        return reader;
    }
};

#endif
