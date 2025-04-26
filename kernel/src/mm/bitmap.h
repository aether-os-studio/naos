#pragma once

#include "libs/klibc.h"

typedef struct
{
    uint8_t *buffer;
    size_t length;
} NA_Bitmap;

void NA_bitmap_init(NA_Bitmap *bitmap, uint8_t *buffer, size_t size);

bool NA_bitmap_get(const NA_Bitmap *bitmap, size_t index);

void NA_bitmap_set(NA_Bitmap *bitmap, size_t index, bool value);

void NA_bitmap_set_range(NA_Bitmap *bitmap, size_t start, size_t end, bool value);

size_t NA_bitmap_find_range(const NA_Bitmap *bitmap, size_t length, bool value);
