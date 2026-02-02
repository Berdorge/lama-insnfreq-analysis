#ifndef BYTEFILE_HPP
#define BYTEFILE_HPP

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <memory>

struct bytefile
{
    std::unique_ptr<uint8_t[]> content;
    uint8_t* public_area_ptr;
    uint8_t* code_ptr;
    uint32_t stringtab_size;
    uint32_t public_symbols_number;
    uint32_t code_length;
    uint32_t ip;
};

bytefile read_file(FILE* f);

inline uint32_t le_bytes_to_uint32_t(uint8_t const* bytes)
{
    return static_cast<uint32_t>(bytes[0]) | (static_cast<uint32_t>(bytes[1]) << 8) |
           (static_cast<uint32_t>(bytes[2]) << 16) | (static_cast<uint32_t>(bytes[3]) << 24);
}

#endif
