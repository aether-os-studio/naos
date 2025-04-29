#pragma once

#include <libs/klibc.h>
#include <fs/vfs/list.h>
#include <arch/arch.h>

#define CURSOR_WIDTH 11
#define CURSOR_HEIGHT 22

struct fb_fix_screeninfo
{
    char id[16];              /* identification string eg "TT Builtin" */
    unsigned long smem_start; /* Start of frame buffer mem */
    /* (physical address) */
    uint32_t smem_len;        /* Length of frame buffer mem */
    uint32_t type;            /* see FB_TYPE_*		*/
    uint32_t type_aux;        /* Interleave for interleaved Planes */
    uint32_t visual;          /* see FB_VISUAL_*		*/
    uint16_t xpanstep;        /* zero if no hardware panning  */
    uint16_t ypanstep;        /* zero if no hardware panning  */
    uint16_t ywrapstep;       /* zero if no hardware ywrap    */
    uint32_t line_length;     /* length of a line in bytes    */
    unsigned long mmio_start; /* Start of Memory Mapped I/O   */
    /* (physical address) */
    uint32_t mmio_len; /* Length of Memory Mapped I/O  */
    uint32_t accel;    /* Indicate to driver which	*/
    /*  specific chip/card we have	*/
    uint16_t reserved[3]; /* Reserved for future compatibility */
};
