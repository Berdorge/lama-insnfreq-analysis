#include "bytefile.hpp"
#include "assertions.hpp"

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <new>
#include <vector>

uint8_t* public_area_ptr;
uint8_t* code_ptr;
uint32_t public_symbols_number;
uint32_t code_length;
uint32_t ip;

static std::vector<uint8_t> contents;

static int read_uint32_t(FILE* f, uint32_t& out)
{
    uint8_t bytes[4];
    if (fread(bytes, 1, 4, f) != 4)
    {
        return -1;
    }
    out = le_bytes_to_uint32_t(bytes);
    return 0;
}

static void read_file_contents(FILE* f) {
    uint8_t buffer[1024];
    size_t read;
    try {
        while ((read = fread(buffer, 1, sizeof(buffer), f)) > 0) {
            contents.insert(contents.end(), buffer, buffer + read);
        }
    } catch (std::bad_alloc&) {
        failure("Failed to allocate memory for input file content");
    }
    if (ferror(f)) {
        failure("Error reading input file: %s", strerror(errno));
    }
    contents.shrink_to_fit();
}

void read_file(FILE* f)
{
    uint32_t stringtab_size;
    uint32_t global_area_size;
    if (read_uint32_t(f, stringtab_size) || read_uint32_t(f, global_area_size) ||
        read_uint32_t(f, public_symbols_number))
    {
        failure("Unable to read input file header");
    }

    read_file_contents(f);

    uint32_t public_area_size = public_symbols_number * 2 * sizeof(uint32_t);
    if (contents.size() < public_area_size)
    {
        failure("Input file content is too small for public area");
    }

    size_t size = contents.size() - public_area_size;
    if (size < stringtab_size)
    {
        failure("Input file content is too small for string table");
    }
    size -= stringtab_size;

    code_length = size;
    public_area_ptr = &contents[0];
    uint8_t* string_ptr = &contents[public_area_size];
    code_ptr = string_ptr + stringtab_size;
}

void check_code_has(size_t n, char const* what)
{
    if (ip + n > code_length)
    {
        failure("Expected %s at offset %zu, got end of bytecode", what, ip);
    }
}

uint8_t next_code_byte()
{
    check_code_has(1, "byte");
    uint8_t value = (code_ptr)[ip];
    ip += 1;
    return value;
}

uint32_t next_code_uint32_t()
{
    check_code_has(4, "4-byte int");
    uint8_t* loc = &code_ptr[ip];
    uint32_t value = (uint32_t)loc[0] | ((uint32_t)loc[1] << 8) | ((uint32_t)loc[2] << 16) |
                     ((uint32_t)loc[3] << 24);
    ip += 4;
    return value;
}
