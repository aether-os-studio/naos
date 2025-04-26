#ifndef _STDIO_H
#define _STDIO_H

#ifdef __cplusplus
extern "C"
{
#endif
#define READ 0x2
#define WRITE 0x4
#define APPEND 0x8
#define BIN 0x0
#define PLUS 0x10
#define EOF -1
#define SEEK_SET 0
#define SEEK_CUR 1
#define SEEK_END 2
#define BUFSIZ (4096 * 2)
#include <libsyscall.h>
  unsigned int getch();
#define getchar getch
  typedef struct FILE
  {
    unsigned int mode;
    unsigned int fileSize;
    unsigned char *buffer;
    unsigned int bufferSize;
    unsigned int p;
    unsigned char eof;
    unsigned char read_flag; // 0 needn't to read, 1 need to read
    char *name;
  } FILE;
  extern FILE *stdout;
  extern FILE *stdin;
  extern FILE *stderr;
#include <stdarg.h>
  int printf(const char *format, ...);
  int sprintf(char *s, const char *format, ...);
  int vsprintf(char *s, const char *format, va_list arg);
  int vsnprintf(char *buf, size_t n, const char *fmt, va_list ap);
  int puts(char *str);
  char *gets(char *str);
#ifdef __cplusplus
}
#endif
#endif
