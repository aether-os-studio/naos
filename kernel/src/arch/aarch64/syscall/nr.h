#pragma once

#include <stdint.h>

/*
 * Linux x86_64系统调用号定义文件 (基于Linux 5.15内核)
 * 说明：
 * 1. 系统调用号可能因内核版本不同而变化，建议通过/usr/include/asm/unistd_64.h获取官方定义
 * 2. 参数传递规则：RDI, RSI, RDX, R10, R8, R9 对应参数1-6
 * 3. 系统调用号通过RAX寄存器传递
 */

/* 文件操作相关 */
#define SYS_READ 0  // read(int fd, void *buf, size_t count)
#define SYS_WRITE 1 // write(int fd, const void *buf, size_t count)
#define SYS_OPEN 2  // open(const char *pathname, int flags, mode_t mode)
#define SYS_CLOSE 3 // close(int fd)
#define SYS_STAT 4  // stat(const char *pathname, struct stat *statbuf)
#define SYS_FSTAT 5 // fstat(int fd, struct stat *statbuf)
#define SYS_LSTAT 6 // lstat(const char *pathname, struct stat *statbuf)
#define SYS_STATFS 137
#define SYS_POLL 7      // poll(struct pollfd *fds, nfds_t nfds, int timeout)
#define SYS_LSEEK 8     // lseek(int fd, off_t offset, int whence)
#define SYS_MMAP 9      // mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset)
#define SYS_MPROTECT 10 // mprotect(void *addr, size_t len, int prot)
#define SYS_MUNMAP 11   // munmap(void *addr, size_t length)
#define SYS_BRK 12      // brk(void *addr)
#define SYS_READV 19
#define SYS_WRITEV 20
#define SYS_DUP 32
#define SYS_DUP2 33
#define SYS_IOCTL 16 // ioctl(int fd, sint cmd, int arg)
#define SYS_GETDENTS64 217
#define SYS_PIPE 22
#define SYS_PIPE2 293
#define SYS_CHDIR 80
#define SYS_GETCWD 79
#define SYS_LINK 86
#define SYS_READLINK 89
#define SYS_FCNTL 72
#define SYS_ACCESS 21
#define SYS_FACCESSAT 269
#define SYS_SELECT 23
#define SYS_PSELECT6 270
#define SYS_EPOLL_CREATE1 291
#define SYS_EPOLL_PWAIT 281
#define SYS_EPOLL_CTL 233
#define SYS_EPOLL_WAIT 232
#define SYS_EPOLL_CREATE 213
#define SYS_EVENTFD2 290
#define SYS_SIGNALFD 282
#define SYS_TIMERFD_CREATE 283
#define SYS_SIGNALFD4 289
#define SYS_FLOCK 73

#define SYS_SOCKET 41
#define SYS_CONNECT 42
#define SYS_ACCEPT 43
#define SYS_BIND 49
#define SYS_LISTEN 50
#define SYS_GETSOCKNAME 51
#define SYS_GETPEERNAME 52
#define SYS_SOCKETPAIR 53
#define SYS_SETSOCKOPT 54
#define SYS_GETSOCKOPT 55
#define SYS_SENDTO 44
#define SYS_RECVFROM 45
#define SYS_RECVMSG 47

/* 进程管理相关 */
#define SYS_NANOSLEEP 35
#define SYS_CLONE 56
#define SYS_FORK 57   // fork()
#define SYS_VFORK 58  // vfork()
#define SYS_EXECVE 59 // execve(const char *pathname, char *const argv[], char *const envp[])
#define SYS_EXIT 60   // exit(int status)
#define SYS_WAIT4 61  // wait4(pid_t pid, int *wstatus, int options, struct rusage *rusage)
#define SYS_KILL 62   // kill(pid_t pid, int sig)
#define SYS_UNAME 63
#define SYS_GETPID 39   // getpid()
#define SYS_GETUID 102  // getuid()
#define SYS_GETGID 104  // getgid()
#define SYS_GETEUID 107 // geteuid()
#define SYS_GETEGID 108 // getegid()
#define SYS_SETPGID 109 // setpgid(int pid, int64_t pgid)
#define SYS_GETPGID 121 // getpgid()
#define SYS_GETPPID 110 // getppid()
#define SYS_SETRESUID 117
#define SYS_GETRESUID 118
#define SYS_GETTID 186
#define SYS_SETFSUID 122
#define SYS_SETFSGID 123
#define SYS_FUTEX 202
#define SYS_EXIT_GROUP 231
#define SYS_GETRLIMIT 97
#define SYS_PRLIMIT64 302

/* 内存管理相关 */
#define SYS_MINCORE 27 // mincore(void *addr, size_t length, unsigned char *vec)

/* 信号处理相关 */
#define SYS_SIGACTION 13   // sigaction(int sig, const struct sigaction *act, struct sigaction *oact)
#define SYS_SIGPROCMASK 14 // sigprocmask(int how, const sigset_t *set, sigset_t *oset)
#define SYS_SIGRETURN 15
#define SYS_SIGALTSTACK 131

#define SYS_PRCTL 157
#define SYS_ARCH_PRCTL 158

#define SYS_SIGNAL 350
#define SYS_SETMASK 351
#define SYS_CLOCK_GETTIME 228

#define SYS_CLOCK_GETRES 229
#define SYS_SET_TID_ADDRESS 218

#define FB_TYPE_PACKED_PIXELS 0      /* Packed Pixels	*/
#define FB_TYPE_PLANES 1             /* Non interleaved planes */
#define FB_TYPE_INTERLEAVED_PLANES 2 /* Interleaved planes	*/
#define FB_TYPE_TEXT 3               /* Text/attributes	*/
#define FB_TYPE_VGA_PLANES 4         /* EGA/VGA planes	*/
#define FB_TYPE_FOURCC 5             /* Type identified by a V4L2 FOURCC */

#define FB_VISUAL_MONO01 0             /* Monochr. 1=Black 0=White */
#define FB_VISUAL_MONO10 1             /* Monochr. 1=White 0=Black */
#define FB_VISUAL_TRUECOLOR 2          /* True color	*/
#define FB_VISUAL_PSEUDOCOLOR 3        /* Pseudo color (like atari) */
#define FB_VISUAL_DIRECTCOLOR 4        /* Direct color */
#define FB_VISUAL_STATIC_PSEUDOCOLOR 5 /* Pseudo color readonly */
#define FB_VISUAL_FOURCC 6             /* Visual identified by a V4L2 FOURCC */

struct fb_fix_screeninfo
{
    char id[16];           /* identification string eg "TT Builtin" */
    uint64_t smem_start;   /* Start of frame buffer mem */
                           /* (physical address) */
    uint32_t smem_len;     /* Length of frame buffer mem */
    uint32_t type;         /* see FB_TYPE_*		*/
    uint32_t type_aux;     /* Interleave for interleaved Planes */
    uint32_t visual;       /* see FB_VISUAL_*		*/
    uint16_t xpanstep;     /* zero if no hardware panning  */
    uint16_t ypanstep;     /* zero if no hardware panning  */
    uint16_t ywrapstep;    /* zero if no hardware ywrap    */
    uint32_t line_length;  /* length of a line in bytes    */
    uint64_t mmio_start;   /* Start of Memory Mapped I/O   */
                           /* (physical address) */
    uint32_t mmio_len;     /* Length of Memory Mapped I/O  */
    uint32_t accel;        /* Indicate to driver which	*/
                           /*  specific chip/card we have	*/
    uint16_t capabilities; /* see FB_CAP_*			*/
    uint16_t reserved[2];  /* Reserved for future compatibility */
};

struct fb_bitfield
{
    uint32_t offset;    /* beginning of bitfield	*/
    uint32_t length;    /* length of bitfield		*/
    uint32_t msb_right; /* != 0 : Most significant bit is */
                        /* right */
};

struct fb_var_screeninfo
{
    uint32_t xres; /* visible resolution		*/
    uint32_t yres;
    uint32_t xres_virtual; /* virtual resolution		*/
    uint32_t yres_virtual;
    uint32_t xoffset; /* offset from virtual to visible */
    uint32_t yoffset; /* resolution			*/

    uint32_t bits_per_pixel;  /* guess what			*/
    uint32_t grayscale;       /* 0 = color, 1 = grayscale,	*/
                              /* >1 = FOURCC			*/
    struct fb_bitfield red;   /* bitfield in fb mem if true color, */
    struct fb_bitfield green; /* else only length is significant */
    struct fb_bitfield blue;
    struct fb_bitfield transp; /* transparency			*/

    uint32_t nonstd; /* != 0 Non standard pixel format */

    uint32_t activate; /* see FB_ACTIVATE_*		*/

    uint32_t height; /* height of picture in mm    */
    uint32_t width;  /* width of picture in mm     */

    uint32_t accel_flags; /* (OBSOLETE) see fb_info.flags */

    /* Timing: All values in pixclocks, except pixclock (of course) */
    uint32_t pixclock;     /* pixel clock in ps (pico seconds) */
    uint32_t left_margin;  /* time from sync to picture	*/
    uint32_t right_margin; /* time from picture to sync	*/
    uint32_t upper_margin; /* time from sync to picture	*/
    uint32_t lower_margin;
    uint32_t hsync_len;   /* length of horizontal sync	*/
    uint32_t vsync_len;   /* length of vertical sync	*/
    uint32_t sync;        /* see FB_SYNC_*		*/
    uint32_t vmode;       /* see FB_VMODE_*		*/
    uint32_t rotate;      /* angle we rotate counter clockwise */
    uint32_t colorspace;  /* colorspace for FOURCC-based modes */
    uint32_t reserved[4]; /* Reserved for future compatibility */
};

struct rlimit
{
    size_t rlim_cur;
    size_t rlim_max;
};

#define FBIOGET_VSCREENINFO 0x4600
#define FBIOPUT_VSCREENINFO 0x4601
#define FBIOGET_FSCREENINFO 0x4602
#define FBIOGETCMAP 0x4604
#define FBIOPUTCMAP 0x4605
#define FBIOPAN_DISPLAY 0x4606
