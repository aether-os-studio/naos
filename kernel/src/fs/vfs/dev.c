#include <fs/vfs/dev.h>
#include <fs/fs_syscall.h>
#include <fs/vfs/sys.h>
#include <drivers/kernel_logger.h>
#include <arch/arch.h>
#include <task/task.h>
#include <drivers/pty.h>

int devfs_id = 0;
vfs_node_t devfs_root = NULL;
vfs_node_t input_root = NULL;

devfs_handle_t devfs_handles[MAX_DEV_NUM];

static int dummy()
{
    return 0;
}

ssize_t devfs_read(fd_t *fd, void *addr, size_t offset, size_t size)
{
    void *file = fd->node->handle;
    devfs_handle_t handle = (devfs_handle_t)file;
    if (handle->read)
    {
        return handle->read(handle->data, offset, addr, size);
    }

    return 0;
}

ssize_t devfs_write(fd_t *fd, const void *addr, size_t offset, size_t size)
{
    void *file = fd->node->handle;
    devfs_handle_t handle = (devfs_handle_t)file;
    if (handle->write)
    {
        return handle->write(handle->data, offset, addr, size);
    }

    return 0;
}

void devfs_open(void *parent, const char *name, vfs_node_t node)
{
    (void)parent;

    if (node->type & file_dir)
    {
        return;
    }

    for (uint64_t i = 0; i < MAX_DEV_NUM; i++)
    {
        if (devfs_handles[i] != NULL && !strncmp(devfs_handles[i]->name, name, MAX_DEV_NAME_LEN))
        {
            devfs_handle_t handle = devfs_handles[i];
            node->handle = handle;
            if (!strncmp(handle->name, "event", 5))
            {
                dev_input_event_t *event = handle->data;
                event->timesOpened++;
            }
            break;
        }
    }
}

bool devfs_close(void *current)
{
    devfs_handle_t handle = (devfs_handle_t)current;
    if (!strncmp(handle->name, "event", 5))
    {
        dev_input_event_t *event = handle->data;
        event->timesOpened--;
    }
    return false;
}

int devfs_ioctl(devfs_handle_t handle, ssize_t cmd, ssize_t arg)
{
    if (handle->ioctl)
    {
        return handle->ioctl(handle->data, cmd, arg);
    }

    return 0;
}

void *devfs_map(fd_t *fd, void *addr, size_t offset, size_t size, size_t prot, size_t flags)
{
    devfs_handle_t handle = fd->node->handle;

    if (handle->map)
    {
        return handle->map(handle->data, addr, offset, size);
    }

    return NULL;
}

int devfs_mkdir(void *parent, const char *name, vfs_node_t node)
{
    vfs_node_t parent_node = parent;

    vfs_node_t child = vfs_child_append(parent_node, name, NULL);
    child->type = file_dir;
    child->handle = child;
    child->fsid = devfs_id;
    child->handle = child;

    return 0;
}

int devfs_mkfile(void *parent, const char *name, vfs_node_t node)
{
    vfs_node_t parent_node = parent;

    vfs_node_t child = vfs_child_append(parent_node, name, NULL);
    child->type = file_none;
    child->handle = child;
    child->fsid = devfs_id;
    child->handle = child;

    return 0;
}

int devfs_poll(devfs_handle_t handle, size_t event)
{
    if (handle->poll)
    {
        return handle->poll(handle->data, event);
    }

    return 0;
}

static struct vfs_callback callbacks = {
    .mount = (vfs_mount_t)dummy,
    .unmount = (vfs_unmount_t)dummy,
    .open = devfs_open,
    .close = devfs_close,
    .read = devfs_read,
    .write = devfs_write,
    .readlink = (vfs_readlink_t)dummy,
    .mkdir = (vfs_mk_t)devfs_mkdir,
    .mkfile = (vfs_mk_t)devfs_mkfile,
    .link = (vfs_mk_t)dummy,
    .symlink = (vfs_mk_t)dummy,
    .delete = (vfs_del_t)dummy,
    .rename = (vfs_rename_t)dummy,
    .map = (vfs_mapfile_t)devfs_map,
    .stat = (vfs_stat_t)dummy,
    .ioctl = (vfs_ioctl_t)devfs_ioctl,
    .poll = (vfs_poll_t)devfs_poll,
    .resize = (vfs_resize_t)dummy,
    .dup = vfs_generic_dup,
};

ssize_t inputdev_event_read(void *data, uint64_t offset, void *buf, uint64_t len)
{
    dev_input_event_t *event = data;

    ssize_t cnt = (ssize_t)circular_int_read(&event->device_events, buf, len);

    return cnt;
}

ssize_t inputdev_event_write(void *data, uint64_t offset, const void *buf, uint64_t len)
{
    dev_input_event_t *event = data;

    // todo

    return len;
}

ssize_t inputdev_ioctl(void *data, ssize_t request, ssize_t arg)
{
    dev_input_event_t *event = data;
    size_t type = _IOC_TYPE(request);
    size_t dir = _IOC_DIR(request);
    size_t number = _IOC_NR(request);
    size_t size = _IOC_SIZE(request);

    (void)type;
    (void)dir;

    ssize_t ret = -ENOTTY;

    if (number >= 0x20 && number < (0x20 + EV_CNT))
    {
        // we are in EVIOCGBIT(event: 0x20 - x) territory, beware
        return event->event_bit(data, request, (void *)arg);
    }
    else if (number >= 0x40 && number < (0x40 + ABS_CNT))
    {
        // we are in EVIOCGABS(event: 0x40 - x) territory, beware
        return event->event_bit(data, request, (void *)arg);
    }

    if (request == 0x540b) // TCFLSH, idk why don't ask me!
        return 0;

    switch (number)
    {
    case 0x01: // EVIOCGVERSION idk, stolen from vmware
        *((int *)arg) = 0x10001;
        ret = 0;
        break;
    case 0x02: // EVIOCGID
        memcpy((void *)arg, &event->inputid, sizeof(struct input_id));
        ret = 0;
        break;
    case 0x06:
    { // EVIOCGNAME(len)
        int toCopy = MIN(size, (size_t)strlen(event->devname) + 1);
        memcpy((void *)arg, event->devname, toCopy);
        ret = toCopy;
        break;
    }
    case 0x07:
    { // EVIOCGPHYS(len)
        int toCopy = MIN(size, (size_t)strlen(event->physloc) + 1);
        memcpy((void *)arg, event->physloc, toCopy);
        ret = toCopy;
        break;
    }
    case 0x08: // EVIOCGUNIQ()
        if (event->uniq[0])
        {
            int toCopy = MIN(size, (size_t)strlen(event->uniq) + 1);
            memcpy((void *)arg, event->uniq, toCopy);
            ret = toCopy;
        }
        else
        {
            ret = -ENODATA;
        }
        break;
    case 0x09: // EVIOCGPROP()
        int toCopy = MIN(sizeof(size_t), size);
        memcpy((void *)arg, &event->properties, toCopy);
        ret = size;
        break;
    case 0x18: // EVIOCGKEY()
        ret = event->event_bit(data, request, (void *)arg);
        break;
    case 0x19: // EVIOCGLED()
        ret = event->event_bit(data, request, (void *)arg);
        break;
    case 0x1b: // EVIOCGSW()
        ret = event->event_bit(data, request, (void *)arg);
        break;
    default:
        printk("unsupported ioctl! %lx", number);
        ret = -ENOTTY;
        break;
    }

    return ret;
}

ssize_t inputdev_poll(void *data, size_t event)
{
    dev_input_event_t *e = data;
    size_t cnt = circular_int_read_poll(&e->device_events);
    if (cnt > 0 && event & EPOLLIN)
        return EPOLLIN;
    return 0;
}

vfs_node_t regist_dev(const char *name,
                      ssize_t (*read)(void *data, uint64_t offset, void *buf, uint64_t len),
                      ssize_t (*write)(void *data, uint64_t offset, const void *buf, uint64_t len),
                      ssize_t (*ioctl)(void *data, ssize_t cmd, ssize_t arg),
                      ssize_t (*poll)(void *data, size_t event),
                      void *(*map)(void *data, void *addr, uint64_t offset, uint64_t len),
                      void *data)
{
    const char *new_name = name;

    vfs_node_t dev = devfs_root;

    if (strstr(name, "/") != NULL)
    {
        new_name = strstr(name, "/") + 1;
        uint64_t path_len = new_name - name;
        char new_path[64];
        strcpy(new_path, "/dev/");
        strncpy(new_path + 5, name, path_len);
        dev = vfs_open((const char *)new_path);
        if (!dev)
        {
            vfs_mkdir((const char *)new_path);
            dev = vfs_open((const char *)new_path);
            dev->mode = 0644;
        }
    }

    for (uint64_t i = 0; i < MAX_DEV_NUM; i++)
    {
        if (devfs_handles[i] == NULL)
        {
            devfs_handles[i] = malloc(sizeof(struct devfs_handle));
            strncpy(devfs_handles[i]->name, new_name, MAX_DEV_NAME_LEN);
            devfs_handles[i]->read = read;
            devfs_handles[i]->write = write;
            devfs_handles[i]->ioctl = ioctl;
            devfs_handles[i]->poll = poll;
            devfs_handles[i]->map = map;
            devfs_handles[i]->data = data;
            vfs_node_t child = vfs_child_append(dev, devfs_handles[i]->name, NULL);
            child->refcount++;
            child->type = file_block;
            child->fsid = devfs_id;
            if (!strncmp(devfs_handles[i]->name, "std", 3) || !strncmp(devfs_handles[i]->name, "tty", 3))
            {
                child->type = file_stream;
                child->rdev = (4 << 8) | 1;
            }
            else if (!strncmp(devfs_handles[i]->name, "fb", 2))
            {
                child->type = file_stream;
                child->rdev = (29 << 8) | 0;
            }
            else if (!strncmp(devfs_handles[i]->name, "card", 4))
            {
                child->type = file_stream;
                child->rdev = (226 << 8) | 0;
            }
            else if (!strncmp(devfs_handles[i]->name, "event0", 6))
            {
                child->type = file_stream;
                child->rdev = (13 << 8) | 0;
                child->mode = 0660;
                vfs_node_t input_root = vfs_open("/sys/class/input");
                vfs_node_t event0 = vfs_child_append(input_root, "event0", NULL);
                vfs_node_t input_input0 = vfs_child_append(input_root, "input0", NULL);

                vfs_node_t input0 = vfs_open("/sys/devices/platform/i8042/serio0/input/input0");
                vfs_node_t e = vfs_open("/sys/devices/platform/i8042/serio0/input/input0/event0");

                event0->type = file_dir | file_symlink;
                event0->mode = 0644;
                event0->linkto = e;

                input_input0->type = file_dir | file_symlink;
                input_input0->mode = 0644;
                input_input0->linkto = input0;
            }
            else if (!strncmp(devfs_handles[i]->name, "event1", 6))
            {
                child->type = file_stream;
                child->rdev = (13 << 8) | 1;
                child->mode = 0660;
                vfs_node_t input_root = vfs_open("/sys/class/input");
                vfs_node_t event1 = vfs_child_append(input_root, "event1", NULL);
                vfs_node_t input_input1 = vfs_child_append(input_root, "input1", NULL);

                vfs_node_t input1 = vfs_open("/sys/devices/platform/i8042/serio1/input/input1");
                vfs_node_t e = vfs_open("/sys/devices/platform/i8042/serio1/input/input1/event1");

                event1->type = file_dir | file_symlink;
                event1->mode = 0644;
                event1->linkto = e;

                input_input1->type = file_dir | file_symlink;
                input_input1->mode = 0644;
                input_input1->linkto = input1;
            }

            child->mode = 0666;

            return child;
        }
    }

    return NULL;
}

ssize_t stdin_read(void *data, uint64_t offset, void *buf, uint64_t len)
{
    char *kernel_buff = malloc(len);

    task_read(current_task, (char *)kernel_buff, len, true);

    uint32_t fr = current_task->tmp_rec_v;
    memcpy(buf, kernel_buff, fr);

    free(kernel_buff);

    return fr;
}

ssize_t stdout_write(void *data, uint64_t offset, const void *buf, uint64_t len)
{
    (void)data;
    (void)offset;

    serial_printk((char *)buf, len);
    os_terminal_write(buf, len);

    return (ssize_t)len;
}

ssize_t stdio_ioctl(void *data, ssize_t cmd, ssize_t arg)
{
    return -ENOTTY;
}

bool ioSwitch = false;

ssize_t stdio_poll(void *data, size_t events)
{
    ssize_t revents = 0;
    if (events & EPOLLERR || events & EPOLLPRI)
        return 0;

    if (events & EPOLLIN && ioSwitch)
        revents |= EPOLLIN;
    if (events & EPOLLOUT)
        revents |= EPOLLOUT;
    ioSwitch = !ioSwitch;
    return revents;
}

void stdio_init()
{
    regist_dev("stdin", stdin_read, NULL, stdio_ioctl, stdio_poll, NULL, NULL);
    regist_dev("stdout", NULL, stdout_write, stdio_ioctl, stdio_poll, NULL, NULL);
    regist_dev("stderr", NULL, stdout_write, stdio_ioctl, stdio_poll, NULL, NULL);

    regist_dev("tty", stdin_read, stdout_write, stdio_ioctl, stdio_poll, NULL, NULL);
    regist_dev("tty0", stdin_read, stdout_write, stdio_ioctl, stdio_poll, NULL, NULL);
    regist_dev("tty1", stdin_read, stdout_write, stdio_ioctl, stdio_poll, NULL, NULL);
}

uint64_t next = 0;

ssize_t random_dev_read(void *data, uint64_t offset, void *buf, uint64_t len)
{
    tm time;
    time_read(&time);
    next = mktime(&time);
    next = next * 1103515245 + 12345;
    return ((unsigned)(next / 65536) % 32768);
}

ssize_t null_dev_read(void *data, uint64_t offset, void *buf, uint64_t len)
{
    (void)data;
    (void)offset;
    (void)buf;
    (void)len;
    return 0;
}

ssize_t null_dev_write(void *data, uint64_t offset, const void *buf, uint64_t len)
{
    (void)data;
    (void)offset;
    (void)buf;
    (void)len;
    return 0;
}

static uint32_t simple_rand()
{
    tm time;
    time_read(&time);
    uint32_t seed = mktime(&time);
    seed = (seed * 1103515245 + 12345) & 0x7FFFFFFF;
    return seed;
}

ssize_t urandom_dev_read(void *data, uint64_t offset, void *buf, uint64_t len)
{
    for (uint64_t i = 0; i < len; i++)
    {
        ((uint8_t *)buf)[i] = (uint8_t)(simple_rand() & 0xFF);
    }
    return len;
}

ssize_t urandom_dev_write(void *data, uint64_t offset, const void *buf, uint64_t len)
{
    return len;
}

ssize_t urandom_dev_ioctl(void *data, ssize_t cmd, ssize_t arg)
{
    switch (cmd)
    {
    default:
        return -ENOTTY;
    }
}
ssize_t kmsg_read(void *data, uint64_t offset, void *buf, uint64_t len)
{
    return len;
}

ssize_t kmsg_write(void *data, uint64_t offset, const void *buf, uint64_t len)
{
    return len;
}

void dev_init()
{
    devfs_id = vfs_regist("devfs", &callbacks);

    devfs_root = vfs_child_append(rootdir, "dev", NULL);
    devfs_root->type = file_dir;
    devfs_root->fsid = devfs_id;
    devfs_root->mode = 0644;
    devfs_root->handle = devfs_root;

    memset(devfs_handles, 0, sizeof(devfs_handles));

    regist_dev("kmsg", kmsg_read, kmsg_write, NULL, NULL, NULL, NULL);
}

void dev_init_after_sysfs()
{
    dev_input_event_t *kb_input_event = malloc(sizeof(dev_input_event_t));
    kb_input_event->inputid.bustype = 0x05;   // BUS_PS2
    kb_input_event->inputid.vendor = 0x045e;  // Microsoft
    kb_input_event->inputid.product = 0x0001; // Generic MS Keyboard
    kb_input_event->inputid.version = 0x0100; // Basic MS Version
    kb_input_event->event_bit = kb_event_bit;
    kb_input_event->device_events.read_ptr = 0;
    kb_input_event->device_events.write_ptr = 0;
    circular_int_init(&kb_input_event->device_events, 4096);
    vfs_node_t kb_node = regist_dev("input/event0", inputdev_event_read, inputdev_event_write, inputdev_ioctl, inputdev_poll, NULL, kb_input_event);
    dev_input_event_t *mouse_input_event = malloc(sizeof(dev_input_event_t));
    mouse_input_event->inputid.bustype = 0x05;   // BUS_PS2
    mouse_input_event->inputid.vendor = 0x045e;  // Microsoft
    mouse_input_event->inputid.product = 0x00b4; // Generic MS Mouse
    mouse_input_event->inputid.version = 0x0100; // Basic MS Version
    mouse_input_event->event_bit = mouse_event_bit;
    mouse_input_event->device_events.read_ptr = 0;
    mouse_input_event->device_events.write_ptr = 0;
    circular_int_init(&mouse_input_event->device_events, 4096);
    vfs_node_t mouse_node = regist_dev("input/event1", inputdev_event_read, inputdev_event_write, inputdev_ioctl, inputdev_poll, NULL, mouse_input_event);

    regist_dev("null", null_dev_read, null_dev_write, NULL, NULL, NULL, NULL);
    regist_dev("random", random_dev_read, NULL, NULL, NULL, NULL, NULL);
    regist_dev("urandom", urandom_dev_read, urandom_dev_write, urandom_dev_ioctl, NULL, NULL, NULL);

    vfs_node_t shm_node = vfs_child_append(devfs_root, "shm", NULL);
    shm_node->type = file_dir;
    shm_node->mode = 0644;

    pty_init();
    ptmx_init();
    pts_init();
}

void circular_int_init(circular_int_t *circ, size_t size)
{
    circ->read_ptr = 0;
    circ->write_ptr = 0;
    circ->buff_size = size;
    circ->buff = malloc(size);
    circ->lock_read.lock = 0;
    memset(circ->buff, 0, size);
}

size_t circular_int_read(circular_int_t *circ, uint8_t *buff, size_t length)
{
    spin_lock(&circ->lock_read);
    ssize_t write = circ->write_ptr;
    ssize_t read = circ->read_ptr;
    if (write == read)
    {
        spin_unlock(&circ->lock_read);
        return 0;
    }

    size_t toCopy = MIN(CIRC_READABLE(write, read, circ->buff_size), length);

    size_t first_chunk = MIN(circ->buff_size - read, toCopy);
    memcpy(buff, &circ->buff[read], first_chunk);

    if (toCopy > first_chunk)
    {
        memcpy(buff + first_chunk, circ->buff, toCopy - first_chunk);
    }

    circ->read_ptr = (read + toCopy) % circ->buff_size;

    spin_unlock(&circ->lock_read);

    return toCopy;
}

size_t circular_int_write(circular_int_t *circ, const uint8_t *buff, size_t length)
{
    ssize_t write = circ->write_ptr;
    ssize_t read = circ->read_ptr;
    size_t writable = CIRC_WRITABLE(write, read, circ->buff_size);
    if (length > writable)
    {
        return 0; // cannot do this
    }

    for (size_t i = 0; i < length; i++)
    {
        // todo: could optimize this with edge memcpy() operations
        circ->buff[write] = buff[i];
        write = (write + 1) % circ->buff_size;
    }

    circ->write_ptr = write;
    return length;
}

size_t circular_int_read_poll(circular_int_t *circ)
{
    size_t ret = 0;

    ssize_t write = circ->write_ptr;
    ssize_t read = circ->read_ptr;
    ret = CIRC_READABLE(write, read, circ->buff_size);
    return ret;
}

void input_generate_event(dev_input_event_t *item, uint16_t type, uint16_t code, int32_t value)
{
    if (!item || item->timesOpened == 0)
        return;

    struct input_event event;
    memset(&event, 0, sizeof(struct input_event));
    event.sec = nanoTime() / 1000000000ULL;
    event.usec = (nanoTime() % 1000000000ULL) / 1000ULL;
    event.type = type;
    event.code = code;
    event.value = value;

    circular_int_write(&item->device_events, (const void *)&event, sizeof(struct input_event));
}
