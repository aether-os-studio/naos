#include <libs/klibc.h>
#include <mm/mm.h>

char *strdup(const char *s) {
    size_t len = strlen((char *)s);
    char *ptr = (char *)malloc(len + 1);
    if (ptr == NULL)
        return NULL;
    memcpy(ptr, (void *)s, len);
    ptr[len] = '\0';
    return ptr;
}
