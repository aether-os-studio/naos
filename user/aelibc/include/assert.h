#pragma once

#include <libsyscall.h>
#include <stdlib.h>

#define assert(cond) \
    do               \
    {                \
        if (!(cond)) \
        {            \
            abort(); \
        }            \
    } while (0)
