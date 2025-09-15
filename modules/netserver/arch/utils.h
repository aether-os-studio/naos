#pragma once

#include <libs/klibc.h>
#include <libs/aether/mm.h>

typedef struct LLheader LLheader;

struct LLheader
{
    LLheader *next;
    // ...
};

void *LinkedListAllocate(void **LLfirstPtr, uint32_t structSize);
bool LinkedListUnregister(void **LLfirstPtr, const void *LLtarget);
bool LinkedListRemove(void **LLfirstPtr, void *LLtarget);
bool LinkedListDuplicate(void **LLfirstPtrSource, void **LLfirstPtrTarget,
                         uint32_t structSize);
void LinkedListPushFrontUnsafe(void **LLfirstPtr, void *LLtarget);
