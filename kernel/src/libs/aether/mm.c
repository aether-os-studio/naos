#include <libs/aether/mm.h>
#include <mod/dlinker.h>

EXPORT_SYMBOL(get_physical_memory_offset);
EXPORT_SYMBOL(get_current_page_dir);

EXPORT_SYMBOL(alloc_frames);
EXPORT_SYMBOL(free_frames);
EXPORT_SYMBOL(alloc_frames_dma32);
EXPORT_SYMBOL(free_frames_dma32);
EXPORT_SYMBOL(alloc_frames_bytes);
EXPORT_SYMBOL(free_frames_bytes);
EXPORT_SYMBOL(alloc_frames_bytes_dma32);
EXPORT_SYMBOL(free_frames_bytes_dma32);

EXPORT_SYMBOL(malloc);
EXPORT_SYMBOL(realloc);
EXPORT_SYMBOL(calloc);
EXPORT_SYMBOL(free);

EXPORT_SYMBOL(map_page_range);
EXPORT_SYMBOL(unmap_page_range);

EXPORT_SYMBOL(translate_address);

EXPORT_SYMBOL(general_map);

EXPORT_SYMBOL(memset);
EXPORT_SYMBOL(memcpy);
EXPORT_SYMBOL(memmove);
EXPORT_SYMBOL(memcmp);
EXPORT_SYMBOL(strlen);
EXPORT_SYMBOL(strnlen);
EXPORT_SYMBOL(strcpy);
EXPORT_SYMBOL(strncpy);
EXPORT_SYMBOL(strcmp);
EXPORT_SYMBOL(strncmp);
EXPORT_SYMBOL(strdup);
