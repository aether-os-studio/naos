#include <mm/bitmap.h>

void bitmap_init(Bitmap *bitmap, uint64_t *buffer, size_t size)
{
    bitmap->buffer = buffer;
    bitmap->length = size * 64;
    memset(buffer, 0, size);
}

bool bitmap_get(const Bitmap *bitmap, size_t index)
{
    size_t word_index = index / 64;
    size_t bit_index = index % 64;
    return (bitmap->buffer[word_index] >> bit_index) & 1;
}

void bitmap_set(Bitmap *bitmap, size_t index, bool value)
{
    size_t word_index = index / 64;
    size_t bit_index = index % 64;
    if (value)
    {
        bitmap->buffer[word_index] |= ((size_t)1UL << bit_index);
    }
    else
    {
        bitmap->buffer[word_index] &= ~((size_t)1UL << bit_index);
    }
}

void bitmap_set_range(Bitmap *bitmap, size_t start, size_t end, bool value)
{
    if (start >= end || start >= bitmap->length)
        return;

    size_t start_word = (start + 63) / 64;
    size_t end_word = end / 64;

    for (size_t i = start; i < start_word * 64 && i < end; i++)
    {
        bitmap_set(bitmap, i, value);
    }

    if (start_word > end_word)
    {
        return;
    }

    if (start_word < end_word)
    {
        size_t fill_value = value ? (size_t)-1 : 0;
        for (size_t i = start_word; i < end_word; i++)
        {
            bitmap->buffer[i] = fill_value;
        }
    }

    for (size_t i = end_word * 64; i <= end; i++)
    {
        bitmap_set(bitmap, i, value);
    }
}

size_t bitmap_find_range_from(const Bitmap *bitmap, size_t length, bool value, size_t start_from)
{
    size_t count = 0, start_index = (size_t)-1;
    size_t word_match = value ? (size_t)-1 : 0;
    size_t current_word_idx = start_from / 64;

    for (size_t word_idx = current_word_idx; word_idx < bitmap->length / 64; word_idx++)
    {
        size_t current_word = bitmap->buffer[word_idx];
        size_t bit_start = (word_idx == current_word_idx) ? start_from % 64 : 0;

        if (current_word == word_match)
        {
            // 处理起始偏移
            size_t valid_bits = 64 - bit_start;
            if (count == 0)
            {
                start_index = word_idx * 64 + bit_start;
            }
            count += valid_bits;
            if (count >= length)
            {
                return start_index;
            }
        }
        else
        {
            // 逐bit扫描时保持跨word计数
            for (size_t bit = bit_start; bit < 64; bit++)
            {
                bool bit_value = (current_word >> bit) & 1;
                if (bit_value == value)
                {
                    if (count == 0)
                    {
                        start_index = word_idx * 64 + bit;
                    }
                    if (++count >= length)
                    {
                        return start_index;
                    }
                }
                else
                {
                    count = 0;
                    start_index = (size_t)-1;
                }
            }
        }
    }
    return (size_t)-1;
}

size_t bitmap_find_range(const Bitmap *bitmap, size_t length, bool value)
{
    return bitmap_find_range_from(bitmap, length, value, 0);
}
