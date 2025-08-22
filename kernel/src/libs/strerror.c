#include "strerror.h"

static const struct errmsgstr_t
{
#define E(n, s) char str##n[sizeof(s)];
#include "__strerror.h"
#undef E
} errmsgstr = {
#define E(n, s) s,
#include "__strerror.h"
#undef E
};

static const unsigned short errmsgidx[] = {
#define E(n, s) [n] = offsetof(struct errmsgstr_t, str##n),
#include "__strerror.h"
#undef E
};

char *strerror(int e)
{
    const char *s;
    if (e >= sizeof errmsgidx / sizeof *errmsgidx)
        e = 0;
    s = (char *)&errmsgstr + errmsgidx[e];
    return s;
}
