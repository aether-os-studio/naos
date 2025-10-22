#include <drivers/tty.h>
#include <drivers/fbtty.h>
#include <mm/mm.h>
#define FLANTERM_IN_FLANTERM
#include <libs/flanterm/flanterm_private.h>
#include <libs/flanterm/flanterm.h>
#include <libs/flanterm/flanterm_backends/fb_private.h>
#include <libs/flanterm/flanterm_backends/fb.h>

void terminal_flush(tty_t *session) { flanterm_flush(session->terminal); }

size_t terminal_read(tty_t *device, char *buf, size_t count) { return 0; }

int terminal_ioctl(tty_t *device, uint32_t cmd, uint64_t arg) {
    struct flanterm_context *ft_ctx = device->terminal;
    struct flanterm_fb_context *fb_ctx = device->terminal;
    switch (cmd) {
    case TIOCGWINSZ:
        *(struct winsize *)arg = (struct winsize){
            .ws_xpixel = fb_ctx->width,
            .ws_ypixel = fb_ctx->height,
            .ws_col = ft_ctx->cols,
            .ws_row = ft_ctx->rows,
        };
        return 0;
    case TIOCSCTTY:
        return 0;
    case TIOCGPGRP:
        int *pid = (int *)arg;
        *pid = device->at_process_group_id;
        return 0;
    case TIOCSPGRP:
        device->at_process_group_id = *(int *)arg;
        return 0;
    case TCGETS:
        if (check_user_overflow(arg, sizeof(termios))) {
            return -EFAULT;
        }
        memcpy((void *)arg, &device->termios, sizeof(termios));
        return 0;
    case TCSETS:
        if (check_user_overflow(arg, sizeof(termios))) {
            return -EFAULT;
        }
        memcpy(&device->termios, (void *)arg, sizeof(termios));
        return 0;
    case TCSETSW:
        if (check_user_overflow(arg, sizeof(termios))) {
            return -EFAULT;
        }
        memcpy(&device->termios, (void *)arg, sizeof(termios));
        return 0;
    case TIOCSWINSZ:
        return 0;
    case KDGETMODE:
        *(int *)arg = device->tty_mode;
        return 0;
    case KDSETMODE:
        device->tty_mode = *(int *)arg;
        return 0;
    case KDGKBMODE:
        *(int *)arg = device->tty_kbmode;
        return 0;
    case KDSKBMODE:
        device->tty_kbmode = *(int *)arg;
        return 0;
    case VT_SETMODE:
        memcpy(&device->current_vt_mode, (void *)arg, sizeof(struct vt_mode));
        return 0;
    case VT_GETMODE:
        memcpy((void *)arg, &device->current_vt_mode, sizeof(struct vt_mode));
        return 0;
    case VT_ACTIVATE:
        return 0;
    case VT_WAITACTIVE:
        return 0;
    case VT_GETSTATE:
        struct vt_state *state = (struct vt_state *)arg;
        state->v_active = 1; // 当前活动终端
        state->v_state = 0;  // 状态标志
        return 0;
    case VT_OPENQRY:
        *(int *)arg = 1;
        return 0;
    case TIOCNOTTY:
        return 0;
    case TCSETSF:
        memcpy(&device->termios, (void *)arg, sizeof(termios));
        return 0;
    case TCFLSH:
        return 0;
    default:
        return -EINVAL;
    }
}

int terminal_poll(tty_t *device, int events) { return 0; }

spinlock_t terminal_write_lock = {0};

size_t terminal_write(tty_t *device, const char *buf, size_t count) {
    spin_lock(&terminal_write_lock);
    flanterm_write(device->terminal, buf, count);
    spin_unlock(&terminal_write_lock);
    return count;
}

uint64_t create_session_terminal(tty_t *session) {
    if (session->device == NULL)
        return -ENODEV;
    if (session->device->type != TTY_DEVICE_GRAPHI)
        return -EINVAL;
    struct tty_graphics_ *framebuffer = session->device->private_data;
    struct flanterm_context *fl_context = flanterm_fb_init(
        NULL, NULL, (void *)framebuffer->address, framebuffer->width,
        framebuffer->height, framebuffer->pitch, framebuffer->red_mask_size,
        framebuffer->red_mask_shift, framebuffer->green_mask_size,
        framebuffer->green_mask_shift, framebuffer->blue_mask_size,
        framebuffer->blue_mask_shift, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
        NULL, 0, 0, 0, 0, 0, 0);
    session->terminal = fl_context;
    session->ops.flush = terminal_flush;
    session->ops.ioctl = terminal_ioctl;
    session->ops.poll = terminal_poll;
    session->ops.read = terminal_read;
    session->ops.write = terminal_write;
    return EOK;
}
