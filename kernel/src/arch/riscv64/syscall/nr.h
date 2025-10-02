#pragma once

#include <libs/klibc.h>

#define SYS_IO_SETUP 0
#define SYS_IO_DESTROY 1
#define SYS_IO_SUBMIT 2
#define SYS_IO_CANCEL 3
#define SYS_IO_GETEVENTS 4
#define SYS_SETXATTR 5
#define SYS_LSETXATTR 6
#define SYS_FSETXATTR 7
#define SYS_GETXATTR 8
#define SYS_LGETXATTR 9
#define SYS_FGETXATTR 10
#define SYS_LISTXATTR 11
#define SYS_LLISTXATTR 12
#define SYS_FLISTXATTR 13
#define SYS_REMOVEXATTR 14
#define SYS_LREMOVEXATTR 15
#define SYS_FREMOVEXATTR 16
#define SYS_GETCWD 17
#define SYS_LOOKUP_DCOOKIE 18
#define SYS_EVENTFD2 19
#define SYS_EPOLL_CREATE1 20
#define SYS_EPOLL_CTL 21
#define SYS_EPOLL_PWAIT 22
#define SYS_DUP 23
#define SYS_DUP3 24
#define SYS_FCNTL 25
#define SYS_INOTIFY_INIT1 26
#define SYS_INOTIFY_ADD_WATCH 27
#define SYS_INOTIFY_RM_WATCH 28
#define SYS_IOCTL 29
#define SYS_IOPRIO_SET 30
#define SYS_IOPRIO_GET 31
#define SYS_FLOCK 32
#define SYS_MKNODAT 33
#define SYS_MKDIRAT 34
#define SYS_UNLINKAT 35
#define SYS_SYMLINKAT 36
#define SYS_LINKAT 37
#define SYS_RENAMEAT 38
#define SYS_UMOUNT 39
#define SYS_MOUNT 40
#define SYS_PIVOT_ROOT 41
#define SYS_NI_SYSCALL 42
#define SYS_STATFS 43
#define SYS_FSTATFS 44
#define SYS_TRUNCATE 45
#define SYS_FTRUNCATE 46
#define SYS_FALLOCATE 47
#define SYS_FACCESSAT 48
#define SYS_CHDIR 49
#define SYS_FCHDIR 50
#define SYS_CHROOT 51
#define SYS_FCHMOD 52
#define SYS_FCHMODAT 53
#define SYS_FCHOWNAT 54
#define SYS_FCHOWN 55
#define SYS_OPENAT 56
#define SYS_CLOSE 57
#define SYS_VHANGUP 58
#define SYS_PIPE2 59
#define SYS_QUOTACTL 60
#define SYS_GETDENTS64 61
#define SYS_LSEEK 62
#define SYS_READ 63
#define SYS_WRITE 64
#define SYS_READV 65
#define SYS_WRITEV 66
#define SYS_PREAD64 67
#define SYS_PWRITE64 68
#define SYS_PREADV 69
#define SYS_PWRITEV 70
#define SYS_SENDFILE64 71
#define SYS_PSELECT6_TIME32 72
#define SYS_PPOLL_TIME32 73
#define SYS_SIGNALFD4 74
#define SYS_VMSPLICE 75
#define SYS_SPLICE 76
#define SYS_TEE 77
#define SYS_READLINKAT 78
#define SYS_NEWFSTATAT 79
#define SYS_NEWFSTAT 80
#define SYS_SYNC 81
#define SYS_FSYNC 82
#define SYS_FDATASYCN 83
#define SYS_SYNC_FILE_RANGE 84
#define SYS_TIMERFD_CREATE 85
#define SYS_ACCT 89
#define SYS_CAPGET 90
#define SYS_CAPSET 91
#define SYS_PERSONALITY 92
#define SYS_EXIT 93
#define SYS_EXIT_GROUP 94
#define SYS_WAITID 95
#define SYS_SET_TID_ADDRESS 96
#define SYS_UNSHARE 97
#define SYS_SET_ROBUST_LIST 99
#define SYS_GET_ROBUST_LIST 100
#define SYS_NANOSLEEP 101
#define SYS_GETITIMER 102
#define SYS_SETITIMER 103
#define SYS_KEXEC_LOAD 104
#define SYS_INIT_MODULE 105
#define SYS_DELETE_MODULE 106
#define SYS_TIMER_CREATE 107
#define SYS_TIMER_DELETE 111
#define SYS_SYSLOG 116
#define SYS_PTRACE 117
#define SYS_SCHED_SETPARAM 118
#define SYS_SCHED_SETSCHEDULER 119
#define SYS_SCHED_GETSCHEDULER 120
#define SYS_SCHED_GETPARAM 121
#define SYS_SCHED_SETAFFINITY 122
#define SYS_SCHED_GETAFFINITY 123
#define SYS_SCHED_YIELD 124
#define SYS_SCHED_GET_PRIORITY_MAX 125
#define SYS_SCHED_GET_PRIORITY_MIN 126
#define SYS_RESTART_SYSCALL 128
#define SYS_KILL 129
#define SYS_TKILL 130
#define SYS_TGKILL 131
#define SYS_SIGALTSTACK 132
#define SYS_RT_SIGSUSPEND 133
#define SYS_RT_SIGACTION 134
#define SYS_RT_SIGPROCMASK 135
#define SYS_RT_SIGPENDING 136
#define SYS_RT_SIGTIMEDWAIT_TIME32 137
#define SYS_RT_SIGQUEUEINFO 138
#define SYS_SETPRIORITY 140
#define SYS_GETPRIORITY 141
#define SYS_REBOOT 142
#define SYS_GETREGID 143
#define SYS_SETGID 144
#define SYS_SETREUID 145
#define SYS_SETUID 146
#define SYS_SETRESUID 147
#define SYS_GETRESUID 148
#define SYS_SETRESUID_ 149
#define SYS_GETRESUID_ 150
#define SYS_SETFSUID 151
#define SYS_SETFSUID_ 152
#define SYS_TIMES 153
#define SYS_SETPGID 154
#define SYS_GETPGID 155
#define SYS_GETSID 156
#define SYS_SETSID 157
#define SYS_GETGROUPS 158
#define SYS_SETGROUPS 159
#define SYS_NEWUNAME 160
#define SYS_SETHOSTNAME 161
#define SYS_SETDOMAINNAME 162
#define SYS_GETRLIMIT 163
#define SYS_SETRLIMIT 164
#define SYS_GETRUSAGE 165
#define SYS_UMASK 166
#define SYS_PRCTL 167
#define SYS_GETCPU 168
#define SYS_GETTIMEOFDAY 169
#define SYS_SETTIMEOFDAY 170
#define SYS_ADJTIMEX 171
#define SYS_GETPID 172
#define SYS_GETPPID 173
#define SYS_GETUID 174
#define SYS_GETEUID 175
#define SYS_GETGID 176
#define SYS_GETEGID 177
#define SYS_GETTID 178
#define SYS_SYSINFO 179
#define SYS_MQ_OPEN 180
#define SYS_MQ_UNLINK 181
#define SYS_MQ_NOTIFY 184
#define SYS_MQ_GETSETATTR 185
#define SYS_MSGGET 186
#define SYS_MSGCTL 187
#define SYS_MSGRCV 188
#define SYS_MSGSND 189
#define SYS_SEMGET 190
#define SYS_SEMCTL 191
#define SYS_SEMOP 193
#define SYS_SHMGET 194
#define SYS_SHMCTL 195
#define SYS_SHMAT 196
#define SYS_SHMDT 197
#define SYS_SOCKET 198
#define SYS_SOCKETPAIR 199
#define SYS_BIND 200
#define SYS_LISTEN 201
#define SYS_ACCEPT 202
#define SYS_CONNECT 203
#define SYS_GETSOCKNAME 204
#define SYS_GETPEERNAME 205
#define SYS_SENDTO 206
#define SYS_RECVFROM 207
#define SYS_SETSOCKOPT 208
#define SYS_GETSOCKOPT 209
#define SYS_SHUTDOWN 210
#define SYS_SENDMSG 211
#define SYS_RECVMSG 212
#define SYS_READAHEAD 213
#define SYS_BRK 214
#define SYS_MUNMAP 215
#define SYS_MREMAP 216
#define SYS_ADD_KEY 217
#define SYS_REQUEST_KEY 218
#define SYS_KEYCTL 219
#define SYS_CLONE 220
#define SYS_EXECVE 221
#define SYS_MMAP 222
#define SYS_FADVISE64_64 223
#define SYS_SWAPON 224
#define SYS_SWAPOFF 225
#define SYS_MPROTECT 226
#define SYS_MSYNC 227
#define SYS_MLOCK 228
#define SYS_MUNLOCK 229
#define SYS_MLOCKALL 230
#define SYS_MUNLOCKALL 231
#define SYS_MINCORE 232
#define SYS_MADVISE 233
#define SYS_REMAP_FILE_PAGES 234
#define SYS_MBIND 235
#define SYS_GET_MEMPOLICY 236
#define SYS_SET_MEMPOLICY 237
#define SYS_MIGRATE_PAGES 238
#define SYS_MOVE_PAGES 239
#define SYS_RT_TGSIGQUEUEINFO 240
#define SYS_PERF_EVENT_OPEN 241
#define SYS_ACCEPT4 242
#define SYS_RECVMMSG_TIME32 243
#define SYS_WAIT4 260
#define SYS_PRLIMIT64 261
#define SYS_FANOTIFY_INIT 262
#define SYS_FANOTIFY_MARK 263
#define SYS_NAME_TO_HANDLE_AT 264
#define SYS_OPEN_BY_HANDLE_AT 265
#define SYS_SYNCFS 267
#define SYS_SETNS 268
#define SYS_SENDMMSG 269
#define SYS_PROCESS_VM_READV 270
#define SYS_PROCESS_VM_WRITEV 271
#define SYS_KCMP 272
#define SYS_FINIT_MODULE 273
#define SYS_SCHED_SETATTR 274
#define SYS_SCHED_GETATTR 275
#define SYS_RENAMEAT2 276
#define SYS_SECCOMP 277
#define SYS_GETRANDOM 278
#define SYS_MEMFD_CREATE 279
#define SYS_BPF 280
#define SYS_EXECVEAT 281
#define SYS_USERFAULTFD 282
#define SYS_MEMBARRIER 283
#define SYS_MLOCK2 284
#define SYS_COPY_FILE_RANGE 295
#define SYS_PREADV2 286
#define SYS_PREADV3 287
#define SYS_PKEY_MPROTECT 288
#define SYS_PKEY_ALLOC 289
#define SYS_PKEY_FREE 290
#define SYS_STATX 291
#define SYS_RSEQ 293
#define SYS_KEXEC_FILE_LOAD 294
#define SYS_CLOCK_GETTIME 403
#define SYS_CLOCK_SETTIME 404
#define SYS_CLOCK_ADJTIME 405
#define SYS_CLOCK_GETRES 406
#define SYS_CLOCK_NANOSLEEP 407
#define SYS_TIMER_GETTIME 408
#define SYS_TIMER_SETTIME 409
#define SYS_TIMERFD_GETTIME 410
#define SYS_TIMERFD_SETTIME 411
#define SYS_UTIMENSAT 412
#define SYS_IO_PGETEVENTS 416
#define SYS_MQ_TIMEDSEND 418
#define SYS_MQ_TIMEDRECEIVE 419
#define SYS_SEMTIMEDOP 420
#define SYS_FUTEX 422
#define SYS_PIDFD_SEND_SIGNAL 424
#define SYS_IO_URING_SETUP 425
#define SYS_IO_URING_ENTER 426
#define SYS_IO_URING_REGISTER 427
#define SYS_OPEN_TREE 428
#define SYS_MOVE_MOUNT 429
#define SYS_FSOPEN 430
#define SYS_FSCONFIG 431
#define SYS_FSMOUNT 432
#define SYS_FSPICK 433
#define SYS_PIDFD_OPEN 434
#define SYS_CLONE3 435
#define SYS_CLOSE_RANGE 436
#define SYS_OPENAT2 437
#define SYS_PIDFD_GETFD 438
#define SYS_FACCESSAT2 439
#define SYS_PROCESS_MADVISE 440

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

struct fb_fix_screeninfo {
    char id[16];           /* identification string eg "TT Builtin" */
    uint64_t smem_start;   /* Start of frame buffer mem */
                           /* (physical address) */
    uint32_t smem_len;     /* length of frame buffer mem */
    uint32_t type;         /* see FB_TYPE_*		*/
    uint32_t type_aux;     /* Interleave for interleaved Planes */
    uint32_t visual;       /* see FB_VISUAL_*		*/
    uint16_t xpanstep;     /* zero if no hardware panning  */
    uint16_t ypanstep;     /* zero if no hardware panning  */
    uint16_t ywrapstep;    /* zero if no hardware ywrap    */
    uint32_t line_length;  /* length of a line in bytes    */
    uint64_t mmio_start;   /* Start of Memory Mapped I/O   */
                           /* (physical address) */
    uint32_t mmio_len;     /* length of Memory Mapped I/O  */
    uint32_t accel;        /* Indicate to driver which	*/
                           /*  specific chip/card we have	*/
    uint16_t capabilities; /* see FB_CAP_*			*/
    uint16_t reserved[2];  /* reserved for future compatibility */
};

struct fb_bitfield {
    uint32_t offset;    /* beginning of bitfield	*/
    uint32_t length;    /* length of bitfield		*/
    uint32_t msb_right; /* != 0 : Most significant bit is */
                        /* right */
};

struct fb_var_screeninfo {
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
    uint32_t reserved[4]; /* reserved for future compatibility */
};

#define FBIOGET_VSCREENINFO 0x4600
#define FBIOPUT_VSCREENINFO 0x4601
#define FBIOGET_FSCREENINFO 0x4602
#define FBIOGETCMAP 0x4604
#define FBIOPUTCMAP 0x4605
#define FBIOPAN_DISPLAY 0x4606
