#ifndef BYTEFILE_HPP
#define BYTEFILE_HPP

#include <cstddef>
#include <cstdint>
#include <cstdio>

extern uint8_t* public_area_ptr;
extern uint8_t* code_ptr;
extern uint32_t public_symbols_number;
extern uint32_t code_length;
extern uint32_t ip;

void read_file(FILE* f);

void check_code_has(size_t n, char const* what);

uint8_t next_code_byte();

uint32_t next_code_uint32_t();

inline uint32_t le_bytes_to_uint32_t(uint8_t const* bytes)
{
    return static_cast<uint32_t>(bytes[0]) | (static_cast<uint32_t>(bytes[1]) << 8) |
           (static_cast<uint32_t>(bytes[2]) << 16) | (static_cast<uint32_t>(bytes[3]) << 24);
}

#endif
