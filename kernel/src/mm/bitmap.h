#pragma once

#include "libs/klibc.h"

typedef struct
{
    uint64_t *buffer;
    size_t length;
} Bitmap;

void bitmap_init(Bitmap *bitmap, uint64_t *buffer, size_t size);

bool bitmap_get(const Bitmap *bitmap, size_t index);

void bitmap_set(Bitmap *bitmap, size_t index, bool value);

void bitmap_set_range(Bitmap *bitmap, size_t start, size_t end, bool value);

size_t bitmap_find_range(const Bitmap *bitmap, size_t length, bool value);

size_t bitmap_find_range_from(const Bitmap *bitmap, size_t length, bool value, size_t start_from);
