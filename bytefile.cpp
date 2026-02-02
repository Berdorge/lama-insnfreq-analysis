#include "bytefile.hpp"
#include "assertions.hpp"

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <new>
#include <vector>

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

static size_t read_file_content(FILE* f, bytefile& bytefile)
{
    long ftold_size;
    if (fseek(f, 0, SEEK_END) == -1 || (ftold_size = ftell(f)) < 0)
    {
        failure("Unable to get input file size. Reason: %s", strerror(errno));
    }
    rewind(f);

    size_t size = ftold_size;
    uint32_t global_area_size;
    if (read_uint32_t(f, bytefile.stringtab_size) || read_uint32_t(f, global_area_size) ||
        read_uint32_t(f, bytefile.public_symbols_number))
    {
        failure("Unable to read input file header");
    }
    if ((ftold_size = ftell(f)) < 0)
    {
        failure("Unable to get input file header size. Reason: %s", strerror(errno));
    }
    size -= ftold_size;

    try
    {
        bytefile.content = std::make_unique<uint8_t[]>(size);
    }
    catch (std::bad_alloc&)
    {
        failure("Unable to allocate memory for input file content");
    }

    if (fread(bytefile.content.get(), 1, size, f) != size)
    {
        failure("Unable to read input file content");
    }

    return size;
}

bytefile read_file(FILE* f)
{
    bytefile result;
    size_t size = read_file_content(f, result);

    uint32_t public_area_size = result.public_symbols_number * 2 * sizeof(uint32_t);
    if (size < public_area_size)
    {
        failure("Input file content is too small for public area");
    }

    size -= public_area_size;
    if (size < result.stringtab_size)
    {
        failure("Input file content is too small for string table");
    }
    size -= result.stringtab_size;

    result.code_length = size;
    result.public_area_ptr = &result.content[0];
    uint8_t* string_ptr = &result.content[public_area_size];
    result.code_ptr = string_ptr + result.stringtab_size;

    return result;
}
