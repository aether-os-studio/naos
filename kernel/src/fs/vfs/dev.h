#pragma once

#include "../partition.h"
#include "vfs.h"

#define MAX_DEV_NUM 128
#define MAX_DEV_NAME_LEN 32

typedef struct devfs_handle
{
    char name[MAX_DEV_NAME_LEN];
    ssize_t (*read)(void *data, uint64_t offset, void *buf, uint64_t len, uint64_t flags);
    ssize_t (*write)(void *data, uint64_t offset, const void *buf, uint64_t len, uint64_t flags);
    ssize_t (*ioctl)(void *data, ssize_t cmd, ssize_t arg);
    ssize_t (*poll)(void *data, size_t event);
    void *(*map)(void *data, void *addr, uint64_t offset, uint64_t len);
    void *data;
} *devfs_handle_t;

typedef struct stdio_handle
{
    int64_t at_process_group_id;
} stdio_handle_t;

extern devfs_handle_t devfs_handles[MAX_DEV_NUM];

typedef struct partition_node
{
    vfs_node_t node;
} *partition_node_t;

extern partition_node_t dev_nodes[MAX_PARTITIONS_NUM];

vfs_node_t regist_dev(const char *name,
                      ssize_t (*read)(void *data, uint64_t offset, void *buf, uint64_t len, uint64_t flags),
                      ssize_t (*write)(void *data, uint64_t offset, const void *buf, uint64_t len, uint64_t flags),
                      ssize_t (*ioctl)(void *data, ssize_t cmd, ssize_t arg),
                      ssize_t (*poll)(void *data, size_t event),
                      void *(*map)(void *data, void *addr, uint64_t offset, uint64_t len),
                      void *data);

void dev_init();
void dev_init_after_sysfs();

#define KDGETMODE 0x4B3B // 获取终端模式命令
#define KDSETMODE 0x4B3A // 设置终端模式命令
#define KD_TEXT 0x00     // 文本模式
#define KD_GRAPHICS 0x01 // 图形模式

#define KDGKBMODE 0x4B44 /* gets current keyboard mode */
#define KDSKBMODE 0x4B45 /* sets current keyboard mode */
#define K_RAW 0x00       // 原始模式（未处理扫描码）
#define K_XLATE 0x01     // 转换模式（生成ASCII）
#define K_MEDIUMRAW 0x02 // 中等原始模式
#define K_UNICODE 0x03   // Unicode模式

#define VT_OPENQRY 0x5600 /* get next available vt */
#define VT_GETMODE 0x5601 /* get mode of active vt */
#define VT_SETMODE 0x5602

#define VT_GETSTATE 0x5603
#define VT_SENDSIG 0x5604

#define VT_ACTIVATE 0x5606   /* make vt active */
#define VT_WAITACTIVE 0x5607 /* wait for vt active */

struct vt_state
{
    uint16_t v_active; // 活动终端号
    uint16_t v_state;  // 终端状态标志
};

struct vt_mode
{
    char mode;    // 终端模式
    char waitv;   // 垂直同步
    short relsig; // 释放信号
    short acqsig; // 获取信号
    short frsig;  // 强制释放信号
};

#define VT_AUTO 0x00    // 自动切换模式
#define VT_PROCESS 0x01 // 进程控制模式

#define _IOC_NRBITS 8
#define _IOC_TYPEBITS 8

/*
 * Let any architecture override either of the following before
 * including this file.
 */

#ifndef _IOC_SIZEBITS
#define _IOC_SIZEBITS 14
#endif

#ifndef _IOC_DIRBITS
#define _IOC_DIRBITS 2
#endif

#define _IOC_NRMASK ((1 << _IOC_NRBITS) - 1)
#define _IOC_TYPEMASK ((1 << _IOC_TYPEBITS) - 1)
#define _IOC_SIZEMASK ((1 << _IOC_SIZEBITS) - 1)
#define _IOC_DIRMASK ((1 << _IOC_DIRBITS) - 1)

#define _IOC_NRSHIFT 0
#define _IOC_TYPESHIFT (_IOC_NRSHIFT + _IOC_NRBITS)
#define _IOC_SIZESHIFT (_IOC_TYPESHIFT + _IOC_TYPEBITS)
#define _IOC_DIRSHIFT (_IOC_SIZESHIFT + _IOC_SIZEBITS)

#define _IOC_DIR(nr) (((nr) >> _IOC_DIRSHIFT) & _IOC_DIRMASK)
#define _IOC_TYPE(nr) (((nr) >> _IOC_TYPESHIFT) & _IOC_TYPEMASK)
#define _IOC_NR(nr) (((nr) >> _IOC_NRSHIFT) & _IOC_NRMASK)
#define _IOC_SIZE(nr) (((nr) >> _IOC_SIZESHIFT) & _IOC_SIZEMASK)

typedef size_t (*event_bit_t)(void *data, uint64_t request, void *arg);

#define EV_SYN 0x00
#define EV_KEY 0x01
#define EV_REL 0x02
#define EV_ABS 0x03
#define EV_MSC 0x04
#define EV_SW 0x05
#define EV_LED 0x11
#define EV_SND 0x12
#define EV_REP 0x14
#define EV_FF 0x15
#define EV_PWR 0x16
#define EV_FF_STATUS 0x17
#define EV_MAX 0x1f
#define EV_CNT (EV_MAX + 1)

#define ABS_MAX 0x3f
#define ABS_CNT (ABS_MAX + 1)

struct input_id
{
    uint16_t bustype;
    uint16_t vendor;
    uint16_t product;
    uint16_t version;
};

struct input_absinfo
{
    int32_t value;
    int32_t minimum;
    int32_t maximum;
    int32_t fuzz;
    int32_t flat;
    int32_t resolution;
};

struct input_event
{
    uint64_t sec;
    uint64_t usec;
    uint16_t type;
    uint16_t code;
    int32_t value;
};

#define CIRC_READABLE(wr, rd, sz) ((wr - rd + sz) % sz)
#define CIRC_WRITABLE(wr, rd, sz) ((rd - wr - 1 + sz) % sz)

typedef struct circular_int
{
    uint8_t *buff;
    size_t buff_size;

    size_t read_ptr;
    size_t write_ptr;

    spinlock_t lock_read;
} circular_int_t;

void circular_int_init(circular_int_t *circ, size_t size);
size_t circular_int_read(circular_int_t *circ, uint8_t *buff, size_t length);
size_t circular_int_write(circular_int_t *circ, const uint8_t *buff, size_t length);
size_t circular_int_read_poll(circular_int_t *circ);

typedef struct dev_input_event
{
    char *devname;
    char *physloc;

    size_t timesOpened;
    circular_int_t device_events;

    struct input_id inputid;

    size_t properties;

    event_bit_t event_bit;

    int clock_id;

    char uniq[32];
} dev_input_event_t;

#define LED_NUML 0x00
#define LED_CAPSL 0x01
#define LED_SCROLLL 0x02
#define LED_COMPOSE 0x03
#define LED_KANA 0x04
#define LED_SLEEP 0x05
#define LED_SUSPEND 0x06
#define LED_MUTE 0x07
#define LED_MISC 0x08
#define LED_MAIL 0x09
#define LED_CHARGING 0x0a
#define LED_MAX 0x0f
#define LED_CNT (LED_MAX + 1)

void input_generate_event(dev_input_event_t *item, uint16_t type, uint16_t code, int32_t value);

void stdio_init();
