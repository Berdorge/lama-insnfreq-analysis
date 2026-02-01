#include "analyzer.hpp"
#include "bytefile.hpp"

#include <cstring>

void reader_t::peek(uint8_t* buffer, size_t n)
{
    check_code_has(n, "bytes");
    for (size_t i = 0; i < n; i++)
    {
        buffer[i] = code_ptr[ip + i];
    }
}

uint32_t reader_t::peek_uint32_t()
{
    uint32_t value = next_code_uint32_t();
    ip -= 4;
    return value;
}

bool hashtable_key::operator==(const hashtable_key& other) const
{
    if (length != other.length)
    {
        return false;
    }
    int diff = memcmp(&code_ptr[ip], &code_ptr[other.ip], length);
    return diff == 0;
}

bool hashtable_entry::operator<(const hashtable_entry& other) const
{
    return value < other.value;
}

hashtable::hashtable(uint32_t size) : size(size), entries(new hashtable_entry[size]())
{
    for (uint32_t i = 0; i < size; i++)
    {
        entries[i].key.length = 0;
    }
}

static hashtable_entry& get_entry(hashtable& hashtable, uint32_t hash, hashtable_key& key)
{
    uint32_t index = (hash * mixing_constant) % hashtable.size;
    while (true)
    {
        if (hashtable.entries[index].key.length == 0)
        {
            return hashtable.entries[index];
        }
        if (hashtable.entries[index].key == key)
        {
            return hashtable.entries[index];
        }
        index = (index + 1) % hashtable.size;
    }
}

void hashtable::mark_occurrence(uint32_t hash, hashtable_key& key)
{
    key.length = ip - key.ip;
    hashtable_entry& entry = get_entry(*this, hash, key);
    if (entry.key.length)
    {
        entry.value++;
    }
    else
    {
        entry.key = key;
        entry.value = 1;
    }
}

uint32_t hashtable::pack()
{
    uint32_t packed_pointer = 0;
    uint32_t unpacked_pointer = 0;

    while (unpacked_pointer < size)
    {
        hashtable_entry& packed_entry = entries[packed_pointer];
        hashtable_entry& unpacked_entry = entries[unpacked_pointer];

        if (packed_entry.key.length == 0 && unpacked_entry.key.length != 0)
        {
            packed_entry = unpacked_entry;
            unpacked_entry.key.length = 0;
            packed_pointer++;
            unpacked_pointer++;
        }
        else if (packed_entry.key.length == 0)
        {
            unpacked_pointer++;
        }
        else
        {
            packed_pointer++;
            unpacked_pointer++;
        }
    }

    return packed_pointer;
}
