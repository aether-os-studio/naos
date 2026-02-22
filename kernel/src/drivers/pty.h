#include <libs/klibc.h>
#include <fs/vfs/dev.h>
#include <fs/fs_syscall.h>
#include <fs/termios.h>

#define PTY_MAX 1024
#define PTY_BUFF_SIZE (256 * 1024)

typedef struct pty_pair {
    vfs_node_t ptmx_node;
    vfs_node_t pts_node;

    struct pty_pair *next;

    mutex_t lock;

    int masterFds;
    int slaveFds;

    termios term;
    struct winsize win;
    uint8_t *bufferMaster;
    uint8_t *bufferSlave;

    int ptrMaster;
    int ptrSlave;

    int tty_kbmode;
    struct vt_mode vt_mode;

    // controlling stuff
    int ctrlSession;
    int ctrlPgid;
    // above not used by ptyIsAssigned() since they aren't cleared

    int frontProcessGroup; // for job control

    int id;
    bool locked; // by default unlocked (hence 0)
} pty_pair_t;

void pty_init();
void ptmx_init();
void pts_init();
