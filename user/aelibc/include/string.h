// string.h
// By min0911_
#ifndef STRING_H_
#define STRING_H_
#ifdef __cplusplus
extern "C"
{
#endif
#include <ctypes.h>
    int strcmp(const char *s1, const char *s2);
    char *strcpy(char *dest, const char *src);
    char *strncpy(char *dest, const char *src, size_t n);
    size_t strlen(const char *s);
    size_t strnlen(const char *s, size_t n);
    char *strcat(char *dest, const char *src);
    char *strncat(char *dest, const char *src, size_t n);
    long strtol(const char *nptr, char **endptr, int base);
    int memcmp(const void *vl, const void *vr, size_t n);
    void *memmove(void *dest, const void *src, int n);
    int strncmp(const char *s1, const char *s2, size_t n);
    void strrev(char *s);
    void F2S(double d, char *str, int l);
    char *strchr(const char *s, int c);
    char *strrchr(const char *s1, int ch);
    double strtod(const char *nptr, char **endptr);
    size_t strcspn(const char *s, const char *c);
    size_t strspn(const char *s, const char *c);
    void *memchr(const void *s, int c, size_t n);
    void *memset(void *dest, int c, size_t n);
    void *memcpy(void *dest, const void *src, size_t n);
    char *strdup(const char *s);

    int isdigit(int c);
    int isalpha(int c);
    int isupper(int c);

    int atoi(const char *nptr);
    long strtol(const char *nptr, char **endptr, int base);
#ifdef __cplusplus
}
#endif
#endif