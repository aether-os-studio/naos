#include <mm/bitmap.h>

void bitmap_init(Bitmap *bitmap, uint8_t *buffer, size_t size) {
    if (!bitmap || !buffer || size == 0)
        return;

    bitmap->buffer = buffer;
    bitmap->length = size * 8;
    bitmap->bitmap_refcount = 1;
    bitmap->lock.lock = 0;
    memset(buffer, 0, size);
}

bool bitmap_get(const Bitmap *bitmap, size_t index) {
    if (!bitmap || !bitmap->buffer || index >= bitmap->length)
        return false;

    size_t word_index = index / 8;
    size_t bit_index = index % 8;
    return (bitmap->buffer[word_index] >> bit_index) & 1;
}

void bitmap_set(Bitmap *bitmap, size_t index, bool value) {
    if (!bitmap || !bitmap->buffer || index >= bitmap->length)
        return;

    size_t word_index = index / 8;
    size_t bit_index = index % 8;
    if (value) {
        bitmap->buffer[word_index] |= ((size_t)1UL << bit_index);
    } else {
        bitmap->buffer[word_index] &= ~((size_t)1UL << bit_index);
    }
}

void bitmap_set_range(Bitmap *bitmap, size_t start, size_t end, bool value) {
    if (!bitmap || !bitmap->buffer || start >= end || start >= bitmap->length) {
        return;
    }

    if (end > bitmap->length)
        end = bitmap->length;

    spin_lock(&bitmap->lock);

    size_t start_word = (start + 7) / 8;
    size_t end_word = end / 8;

    for (size_t i = start; i < MIN(start_word * 8, end); i++) {
        bitmap_set(bitmap, i, value);
    }

    if (start_word > end_word) {
        spin_unlock(&bitmap->lock);
        return;
    }

    if (start_word <= end_word) {
        uint8_t fill_value = value ? (uint8_t)-1 : 0;
        for (size_t i = start_word; i < end_word; i++) {
            bitmap->buffer[i] = fill_value;
        }
    }

    for (size_t i = MAX(end_word * 8, start); i < end; i++) {
        bitmap_set(bitmap, i, value);
    }

    spin_unlock(&bitmap->lock);
}

size_t bitmap_find_range_from(const Bitmap *bitmap, size_t length, bool value,
                              size_t start_from) {
    if (!bitmap || !bitmap->buffer || length == 0 ||
        start_from >= bitmap->length)
        return (size_t)-1;

    spin_lock(&bitmap->lock);

    size_t run_start = 0;
    size_t run_count = 0;

    for (size_t index = start_from; index < bitmap->length; index++) {
        bool bit = (bitmap->buffer[index / 8] >> (index % 8)) & 1;
        if (bit == value) {
            if (run_count == 0)
                run_start = index;
            run_count++;
            if (run_count >= length) {
                spin_unlock(&bitmap->lock);
                return run_start;
            }
        } else {
            run_count = 0;
        }
    }

    spin_unlock(&bitmap->lock);

    return (size_t)-1;
}

size_t bitmap_find_range(const Bitmap *bitmap, size_t length, bool value) {
    return bitmap_find_range_from(bitmap, length, value, 0);
}
