#include <libs/klibc.h>
#include <arch/arch.h>
#include <drivers/kernel_logger.h>

char ub_buf[256];

void serial_print(const char *fmt, ...)
{
    // va_list args;
    // va_start(args, fmt);

    // int len = sprintf(ub_buf, fmt, args);

    // va_end(args);

    // serial_printk(ub_buf, len);
}

#define CRGB(r, g, b) "\033[38;2;" #r ";" #g ";" #b "m"
#define CBRGB(r, g, b) "\033[48;2;" #r ";" #g ";" #b "m"
#define CEND "\033[0m"

#define COLOR_DEBUG CRGB(128, 192, 255)
#define COLOR_INFO CRGB(64, 192, 128)
#define COLOR_WARN CRGB(255, 192, 0)
#define COLOR_ERROR CRGB(255, 128, 64)
#define COLOR_FATAL CRGB(255, 64, 64)

#define STR_DEBUG "[" COLOR_DEBUG "Debug" CEND "] "
#define STR_INFO "[" COLOR_INFO "Info " CEND "] "
#define STR_WARN "[" COLOR_WARN "Warn " CEND "] "
#define STR_ERROR "[" COLOR_ERROR "Error" CEND "] "
#define STR_FATAL "[" COLOR_FATAL "Fatal" CEND "] "

#ifndef _log_func_
#define _log_func_ serial_print
#endif

typedef struct SourceLocation
{
    const char *file;
    uint32_t line;
    uint32_t col;
} SourceLocation;

static inline
    __attribute__((always_inline, nonnull(1, 2), access(read_only, 1, 3), access(read_only, 2, 3))) bool
    _log_memeq_(const void *a, const void *b, __UINTPTR_TYPE__ size)
{
    const __UINT8_TYPE__ *p = (const __UINT8_TYPE__ *)a;
    const __UINT8_TYPE__ *q = (const __UINT8_TYPE__ *)b;
    for (__UINTPTR_TYPE__ i = 0; i < size; i++)
    {
        if (p[i] != q[i])
            return false;
    }

    return true;
}

static __attribute__((nonnull(1))) const char *_log_relative_path_(const char *path)
{
    __INTPTR_TYPE__ i = 0;
    while (path[i] != '\0')
        i++;
    for (__INTPTR_TYPE__ j = i - 10; j >= 0; j--)
    {
        if (_log_memeq_(path + j, "/Aether-OS/", 10))
            return path + j + 10;
    }
    return path;
}

#define _format_(type)                                                                \
    STR_ERROR CRGB(253, 133, 172) "at" CEND " [" CRGB(192, 128, 255) "%s:" CEND CRGB( \
        0, 255, 255) "%u" CEND ":" CRGB(255, 128, 192) "%u " CEND COLOR_ERROR         \
                                                       "UB! " type CEND "\n"

#define ublog(type, file, line, col)                                                       \
    ({                                                                                     \
        _log_func_(_format_(type), _log_relative_path_((file) ?: "<unknown>"), line, col); \
    })

#define UBSCAN_FN(_type_, _version_) void __ubsan_handle_##_type_##_version_

#define HANDLE(_type_, _version_)                                  \
    UBSCAN_FN(_type_, _version_)(const SourceLocation *pos)        \
    {                                                              \
        ublog(#_type_, pos->file, pos->line, pos->col);            \
    }                                                              \
    UBSCAN_FN(_type_, _version_##abort)(const SourceLocation *pos) \
    {                                                              \
        __ubsan_handle_##_type_##_version_(pos);                   \
    }

#define HANDLE_X(_type_, _version_)                                \
    UBSCAN_FN(_type_, _version_)(const SourceLocation *pos)        \
    {                                                              \
        ublog(#_type_, pos->file, pos->line, pos->col);            \
    }                                                              \
    UBSCAN_FN(_type_, _version_##abort)(const SourceLocation *pos) \
    {                                                              \
        __ubsan_handle_##_type_(pos);                              \
    }

HANDLE(add_overflow, );
HANDLE(alignment_assumption, );
HANDLE_X(builtin_unreachable, );
HANDLE(cfi_bad_type, );
HANDLE(cfi_check_fail, );
HANDLE(divrem_overflow, );
HANDLE(dynamic_type_cache_miss, );
HANDLE(float_cast_overflow, );
HANDLE(function_type_mismatch, );
HANDLE(implicit_conversion, );
HANDLE(invalid_builtin, );
HANDLE(invalid_objc_cast, );
HANDLE(load_invalid_value, );
HANDLE(missing_return, );
HANDLE(mul_overflow, );
HANDLE(negate_overflow, );
HANDLE(nonnull_arg, );
HANDLE(nonnull_return, _v1);
HANDLE(nullability_arg, );
HANDLE(nullability_return, _v1);
HANDLE(out_of_bounds, );
HANDLE(pointer_overflow, );
HANDLE(shift_out_of_bounds, );
HANDLE(sub_overflow, );
HANDLE(type_mismatch, _v1);
HANDLE(vla_bound_not_positive, );

void __ubsan_default_options() {}

void __ubsan_on_report() {}

void __ubsan_get_current_report_data() {}
