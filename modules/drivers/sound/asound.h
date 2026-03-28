#pragma once

#include <arch/arch.h>
#include <libs/klibc.h>

#define SNDRV_PROTOCOL_VERSION(major, minor, subminor)                         \
    (((major) << 16) | ((minor) << 8) | (subminor))

#define SNDRV_PCM_VERSION SNDRV_PROTOCOL_VERSION(2, 0, 18)
#define SNDRV_CTL_VERSION SNDRV_PROTOCOL_VERSION(2, 0, 9)

typedef unsigned long snd_pcm_uframes_t;
typedef signed long snd_pcm_sframes_t;
typedef int snd_pcm_access_t;
typedef int snd_pcm_format_t;
typedef int snd_pcm_subformat_t;
typedef int snd_pcm_state_t;
typedef int snd_ctl_elem_type_t;
typedef int snd_ctl_elem_iface_t;

#define SNDRV_PCM_STREAM_PLAYBACK 0
#define SNDRV_PCM_STREAM_CAPTURE 1

#define SNDRV_PCM_ACCESS_MMAP_INTERLEAVED ((snd_pcm_access_t)0)
#define SNDRV_PCM_ACCESS_RW_INTERLEAVED ((snd_pcm_access_t)3)

#define SNDRV_PCM_FORMAT_S8 ((snd_pcm_format_t)0)
#define SNDRV_PCM_FORMAT_U8 ((snd_pcm_format_t)1)
#define SNDRV_PCM_FORMAT_S16_LE ((snd_pcm_format_t)2)
#define SNDRV_PCM_FORMAT_U16_LE ((snd_pcm_format_t)4)
#define SNDRV_PCM_FORMAT_S24_LE ((snd_pcm_format_t)6)
#define SNDRV_PCM_FORMAT_U24_LE ((snd_pcm_format_t)8)
#define SNDRV_PCM_FORMAT_S32_LE ((snd_pcm_format_t)10)
#define SNDRV_PCM_FORMAT_U32_LE ((snd_pcm_format_t)12)
#define SNDRV_PCM_FORMAT_FLOAT_LE ((snd_pcm_format_t)14)
#define SNDRV_PCM_FORMAT_FLOAT64_LE ((snd_pcm_format_t)16)
#define SNDRV_PCM_FORMAT_S24_3LE ((snd_pcm_format_t)32)
#define SNDRV_PCM_FORMAT_U24_3LE ((snd_pcm_format_t)34)

#define SNDRV_PCM_SUBFORMAT_STD ((snd_pcm_subformat_t)0)

#define SNDRV_PCM_INFO_MMAP 0x00000001U
#define SNDRV_PCM_INFO_MMAP_VALID 0x00000002U
#define SNDRV_PCM_INFO_INTERLEAVED 0x00000100U
#define SNDRV_PCM_INFO_RESUME 0x00040000U
#define SNDRV_PCM_INFO_PAUSE 0x00080000U
#define SNDRV_PCM_INFO_SYNC_APPLPTR 0x00000020U

#define SNDRV_PCM_STATE_OPEN ((snd_pcm_state_t)0)
#define SNDRV_PCM_STATE_SETUP ((snd_pcm_state_t)1)
#define SNDRV_PCM_STATE_PREPARED ((snd_pcm_state_t)2)
#define SNDRV_PCM_STATE_RUNNING ((snd_pcm_state_t)3)
#define SNDRV_PCM_STATE_XRUN ((snd_pcm_state_t)4)
#define SNDRV_PCM_STATE_DRAINING ((snd_pcm_state_t)5)
#define SNDRV_PCM_STATE_PAUSED ((snd_pcm_state_t)6)
#define SNDRV_PCM_STATE_SUSPENDED ((snd_pcm_state_t)7)
#define SNDRV_PCM_STATE_DISCONNECTED ((snd_pcm_state_t)8)

#define SNDRV_PCM_TSTAMP_NONE 0
#define SNDRV_PCM_TSTAMP_ENABLE 1

#define SNDRV_PCM_TSTAMP_TYPE_GETTIMEOFDAY 0
#define SNDRV_PCM_TSTAMP_TYPE_MONOTONIC 1
#define SNDRV_PCM_TSTAMP_TYPE_MONOTONIC_RAW 2

#define SNDRV_PCM_AUDIO_TSTAMP_TYPE_COMPAT 0
#define SNDRV_PCM_AUDIO_TSTAMP_TYPE_DEFAULT 1

#define SNDRV_PCM_MMAP_OFFSET_DATA 0x00000000U
#define SNDRV_PCM_MMAP_OFFSET_STATUS 0x82000000U
#define SNDRV_PCM_MMAP_OFFSET_CONTROL 0x83000000U

#define SNDRV_PCM_HW_PARAM_ACCESS 0
#define SNDRV_PCM_HW_PARAM_FORMAT 1
#define SNDRV_PCM_HW_PARAM_SUBFORMAT 2
#define SNDRV_PCM_HW_PARAM_FIRST_MASK SNDRV_PCM_HW_PARAM_ACCESS
#define SNDRV_PCM_HW_PARAM_LAST_MASK SNDRV_PCM_HW_PARAM_SUBFORMAT
#define SNDRV_PCM_HW_PARAM_SAMPLE_BITS 8
#define SNDRV_PCM_HW_PARAM_FRAME_BITS 9
#define SNDRV_PCM_HW_PARAM_CHANNELS 10
#define SNDRV_PCM_HW_PARAM_RATE 11
#define SNDRV_PCM_HW_PARAM_PERIOD_TIME 12
#define SNDRV_PCM_HW_PARAM_PERIOD_SIZE 13
#define SNDRV_PCM_HW_PARAM_PERIOD_BYTES 14
#define SNDRV_PCM_HW_PARAM_PERIODS 15
#define SNDRV_PCM_HW_PARAM_BUFFER_TIME 16
#define SNDRV_PCM_HW_PARAM_BUFFER_SIZE 17
#define SNDRV_PCM_HW_PARAM_BUFFER_BYTES 18
#define SNDRV_PCM_HW_PARAM_TICK_TIME 19
#define SNDRV_PCM_HW_PARAM_FIRST_INTERVAL SNDRV_PCM_HW_PARAM_SAMPLE_BITS
#define SNDRV_PCM_HW_PARAM_LAST_INTERVAL SNDRV_PCM_HW_PARAM_TICK_TIME

#define SNDRV_PCM_HW_PARAMS_NORESAMPLE (1U << 0)
#define SNDRV_PCM_HW_PARAMS_EXPORT_BUFFER (1U << 1)
#define SNDRV_PCM_HW_PARAMS_NO_PERIOD_WAKEUP (1U << 2)

#define SNDRV_PCM_SYNC_PTR_HWSYNC (1U << 0)
#define SNDRV_PCM_SYNC_PTR_APPL (1U << 1)
#define SNDRV_PCM_SYNC_PTR_AVAIL_MIN (1U << 2)

#define SNDRV_CHMAP_UNKNOWN 0
#define SNDRV_CHMAP_NA 1
#define SNDRV_CHMAP_MONO 2
#define SNDRV_CHMAP_FL 3
#define SNDRV_CHMAP_FR 4
#define SNDRV_CHMAP_RL 5
#define SNDRV_CHMAP_RR 6
#define SNDRV_CHMAP_FC 7
#define SNDRV_CHMAP_LFE 8
#define SNDRV_CHMAP_SL 9
#define SNDRV_CHMAP_SR 10

#define SNDRV_CTL_ELEM_TYPE_NONE ((snd_ctl_elem_type_t)0)
#define SNDRV_CTL_ELEM_TYPE_BOOLEAN ((snd_ctl_elem_type_t)1)
#define SNDRV_CTL_ELEM_TYPE_INTEGER ((snd_ctl_elem_type_t)2)
#define SNDRV_CTL_ELEM_TYPE_ENUMERATED ((snd_ctl_elem_type_t)3)
#define SNDRV_CTL_ELEM_TYPE_BYTES ((snd_ctl_elem_type_t)4)
#define SNDRV_CTL_ELEM_TYPE_IEC958 ((snd_ctl_elem_type_t)5)
#define SNDRV_CTL_ELEM_TYPE_INTEGER64 ((snd_ctl_elem_type_t)6)

#define SNDRV_CTL_ELEM_IFACE_CARD ((snd_ctl_elem_iface_t)0)
#define SNDRV_CTL_ELEM_IFACE_HWDEP ((snd_ctl_elem_iface_t)1)
#define SNDRV_CTL_ELEM_IFACE_MIXER ((snd_ctl_elem_iface_t)2)
#define SNDRV_CTL_ELEM_IFACE_PCM ((snd_ctl_elem_iface_t)3)
#define SNDRV_CTL_ELEM_IFACE_RAWMIDI ((snd_ctl_elem_iface_t)4)
#define SNDRV_CTL_ELEM_IFACE_TIMER ((snd_ctl_elem_iface_t)5)
#define SNDRV_CTL_ELEM_IFACE_SEQUENCER ((snd_ctl_elem_iface_t)6)

#define SNDRV_CTL_ELEM_ACCESS_READ (1U << 0)
#define SNDRV_CTL_ELEM_ACCESS_WRITE (1U << 1)
#define SNDRV_CTL_ELEM_ACCESS_READWRITE                                        \
    (SNDRV_CTL_ELEM_ACCESS_READ | SNDRV_CTL_ELEM_ACCESS_WRITE)
#define SNDRV_CTL_ELEM_ACCESS_VOLATILE (1U << 2)
#define SNDRV_CTL_ELEM_ACCESS_TLV_READ (1U << 4)
#define SNDRV_CTL_ELEM_ACCESS_TLV_WRITE (1U << 5)
#define SNDRV_CTL_ELEM_ACCESS_TLV_COMMAND (1U << 6)
#define SNDRV_CTL_ELEM_ACCESS_INACTIVE (1U << 8)

#define SNDRV_CTL_POWER_D0 0x0000
#define SNDRV_CTL_POWER_D1 0x0100
#define SNDRV_CTL_POWER_D2 0x0200
#define SNDRV_CTL_POWER_D3 0x0300
#define SNDRV_CTL_POWER_D3hot (SNDRV_CTL_POWER_D3 | 0x0000)
#define SNDRV_CTL_POWER_D3cold (SNDRV_CTL_POWER_D3 | 0x0001)

#define SNDRV_CTL_ELEM_ID_NAME_MAXLEN 44
#define SNDRV_MASK_MAX 256

typedef struct snd_mask {
    uint32_t bits[(SNDRV_MASK_MAX + 31) / 32];
} snd_mask_t;

typedef struct snd_interval {
    unsigned int min;
    unsigned int max;
    unsigned int openmin : 1;
    unsigned int openmax : 1;
    unsigned int integer : 1;
    unsigned int empty : 1;
} snd_interval_t;

typedef struct snd_pcm_info {
    unsigned int device;
    unsigned int subdevice;
    int stream;
    int card;
    unsigned char id[64];
    unsigned char name[80];
    unsigned char subname[32];
    int dev_class;
    int dev_subclass;
    unsigned int subdevices_count;
    unsigned int subdevices_avail;
    unsigned char pad1[16];
    unsigned char reserved[64];
} snd_pcm_info_t;

typedef struct snd_pcm_hw_params {
    unsigned int flags;
    snd_mask_t
        masks[SNDRV_PCM_HW_PARAM_LAST_MASK - SNDRV_PCM_HW_PARAM_FIRST_MASK + 1];
    snd_mask_t mres[5];
    snd_interval_t intervals[SNDRV_PCM_HW_PARAM_LAST_INTERVAL -
                             SNDRV_PCM_HW_PARAM_FIRST_INTERVAL + 1];
    snd_interval_t ires[9];
    unsigned int rmask;
    unsigned int cmask;
    unsigned int info;
    unsigned int msbits;
    unsigned int rate_num;
    unsigned int rate_den;
    snd_pcm_uframes_t fifo_size;
    unsigned char sync[16];
    unsigned char reserved[48];
} snd_pcm_hw_params_t;

typedef struct snd_pcm_sw_params {
    int tstamp_mode;
    unsigned int period_step;
    unsigned int sleep_min;
    snd_pcm_uframes_t avail_min;
    snd_pcm_uframes_t xfer_align;
    snd_pcm_uframes_t start_threshold;
    snd_pcm_uframes_t stop_threshold;
    snd_pcm_uframes_t silence_threshold;
    snd_pcm_uframes_t silence_size;
    snd_pcm_uframes_t boundary;
    unsigned int proto;
    unsigned int tstamp_type;
    unsigned char reserved[56];
} snd_pcm_sw_params_t;

typedef struct snd_pcm_channel_info {
    unsigned int channel;
    int64_t offset;
    unsigned int first;
    unsigned int step;
} snd_pcm_channel_info_t;

typedef struct snd_pcm_status {
    snd_pcm_state_t state;
    int pad1;
    struct timespec trigger_tstamp;
    struct timespec tstamp;
    snd_pcm_uframes_t appl_ptr;
    snd_pcm_uframes_t hw_ptr;
    snd_pcm_sframes_t delay;
    snd_pcm_uframes_t avail;
    snd_pcm_uframes_t avail_max;
    snd_pcm_uframes_t overrange;
    snd_pcm_state_t suspended_state;
    uint32_t audio_tstamp_data;
    struct timespec audio_tstamp;
    struct timespec driver_tstamp;
    uint32_t audio_tstamp_accuracy;
    unsigned char reserved[20];
} snd_pcm_status_t;

typedef struct snd_pcm_mmap_status {
    snd_pcm_state_t state;
    int pad1;
    snd_pcm_uframes_t hw_ptr;
    struct timespec tstamp;
    snd_pcm_state_t suspended_state;
    struct timespec audio_tstamp;
} snd_pcm_mmap_status_t;

typedef struct snd_pcm_mmap_control {
    snd_pcm_uframes_t appl_ptr;
    snd_pcm_uframes_t avail_min;
} snd_pcm_mmap_control_t;

typedef struct snd_pcm_sync_ptr {
    unsigned int flags;
    union {
        snd_pcm_mmap_status_t status;
        unsigned char reserved[64];
    } s;
    union {
        snd_pcm_mmap_control_t control;
        unsigned char reserved[64];
    } c;
} snd_pcm_sync_ptr_t;

typedef struct snd_xferi {
    snd_pcm_sframes_t result;
    void *buf;
    snd_pcm_uframes_t frames;
} snd_xferi_t;

typedef struct snd_ctl_card_info {
    int card;
    int pad;
    unsigned char id[16];
    unsigned char driver[16];
    unsigned char name[32];
    unsigned char longname[80];
    unsigned char reserved_[16];
    unsigned char mixername[80];
    unsigned char components[128];
} snd_ctl_card_info_t;

typedef struct snd_ctl_elem_id {
    unsigned int numid;
    snd_ctl_elem_iface_t iface;
    unsigned int device;
    unsigned int subdevice;
    unsigned char name[SNDRV_CTL_ELEM_ID_NAME_MAXLEN];
    unsigned int index;
} snd_ctl_elem_id_t;

typedef struct snd_ctl_elem_list {
    unsigned int offset;
    unsigned int space;
    unsigned int used;
    unsigned int count;
    snd_ctl_elem_id_t *pids;
    unsigned char reserved[50];
} snd_ctl_elem_list_t;

typedef struct snd_ctl_elem_info {
    snd_ctl_elem_id_t id;
    snd_ctl_elem_type_t type;
    unsigned int access;
    unsigned int count;
    int owner;
    union {
        struct {
            long min;
            long max;
            long step;
        } integer;
        struct {
            long long min;
            long long max;
            long long step;
        } integer64;
        struct {
            unsigned int items;
            unsigned int item;
            char name[64];
            uint64_t names_ptr;
            unsigned int names_length;
        } enumerated;
        unsigned char reserved[128];
    } value;
    unsigned char reserved[64];
} snd_ctl_elem_info_t;

typedef struct snd_ctl_elem_value {
    snd_ctl_elem_id_t id;
    unsigned int indirect : 1;
    union {
        union {
            long value[128];
            long *value_ptr;
        } integer;
        union {
            long long value[64];
            long long *value_ptr;
        } integer64;
        union {
            unsigned int item[128];
            unsigned int *item_ptr;
        } enumerated;
        union {
            unsigned char data[512];
            unsigned char *data_ptr;
        } bytes;
    } value;
    unsigned char reserved[128];
} snd_ctl_elem_value_t;

#define SNDRV_PCM_IOCTL_PVERSION _IOR('A', 0x00, int)
#define SNDRV_PCM_IOCTL_INFO _IOR('A', 0x01, snd_pcm_info_t)
#define SNDRV_PCM_IOCTL_TSTAMP _IOW('A', 0x02, int)
#define SNDRV_PCM_IOCTL_TTSTAMP _IOW('A', 0x03, int)
#define SNDRV_PCM_IOCTL_USER_PVERSION _IOW('A', 0x04, int)
#define SNDRV_PCM_IOCTL_HW_REFINE _IOWR('A', 0x10, snd_pcm_hw_params_t)
#define SNDRV_PCM_IOCTL_HW_PARAMS _IOWR('A', 0x11, snd_pcm_hw_params_t)
#define SNDRV_PCM_IOCTL_HW_FREE _IO('A', 0x12)
#define SNDRV_PCM_IOCTL_SW_PARAMS _IOWR('A', 0x13, snd_pcm_sw_params_t)
#define SNDRV_PCM_IOCTL_STATUS _IOR('A', 0x20, snd_pcm_status_t)
#define SNDRV_PCM_IOCTL_DELAY _IOR('A', 0x21, snd_pcm_sframes_t)
#define SNDRV_PCM_IOCTL_HWSYNC _IO('A', 0x22)
#define SNDRV_PCM_IOCTL_SYNC_PTR _IOWR('A', 0x23, snd_pcm_sync_ptr_t)
#define SNDRV_PCM_IOCTL_STATUS_EXT _IOWR('A', 0x24, snd_pcm_status_t)
#define SNDRV_PCM_IOCTL_CHANNEL_INFO _IOR('A', 0x32, snd_pcm_channel_info_t)
#define SNDRV_PCM_IOCTL_PREPARE _IO('A', 0x40)
#define SNDRV_PCM_IOCTL_RESET _IO('A', 0x41)
#define SNDRV_PCM_IOCTL_START _IO('A', 0x42)
#define SNDRV_PCM_IOCTL_DROP _IO('A', 0x43)
#define SNDRV_PCM_IOCTL_DRAIN _IO('A', 0x44)
#define SNDRV_PCM_IOCTL_PAUSE _IOW('A', 0x45, int)
#define SNDRV_PCM_IOCTL_REWIND _IOW('A', 0x46, snd_pcm_uframes_t)
#define SNDRV_PCM_IOCTL_RESUME _IO('A', 0x47)
#define SNDRV_PCM_IOCTL_XRUN _IO('A', 0x48)
#define SNDRV_PCM_IOCTL_FORWARD _IOW('A', 0x49, snd_pcm_uframes_t)
#define SNDRV_PCM_IOCTL_WRITEI_FRAMES _IOW('A', 0x50, snd_xferi_t)

#define SNDRV_CTL_IOCTL_PVERSION _IOR('U', 0x00, int)
#define SNDRV_CTL_IOCTL_CARD_INFO _IOR('U', 0x01, snd_ctl_card_info_t)
#define SNDRV_CTL_IOCTL_ELEM_LIST _IOWR('U', 0x10, snd_ctl_elem_list_t)
#define SNDRV_CTL_IOCTL_ELEM_INFO _IOWR('U', 0x11, snd_ctl_elem_info_t)
#define SNDRV_CTL_IOCTL_ELEM_READ _IOWR('U', 0x12, snd_ctl_elem_value_t)
#define SNDRV_CTL_IOCTL_ELEM_WRITE _IOWR('U', 0x13, snd_ctl_elem_value_t)
#define SNDRV_CTL_IOCTL_SUBSCRIBE_EVENTS _IOWR('U', 0x16, int)
#define SNDRV_CTL_IOCTL_PCM_NEXT_DEVICE _IOR('U', 0x30, int)
#define SNDRV_CTL_IOCTL_PCM_INFO _IOWR('U', 0x31, snd_pcm_info_t)
#define SNDRV_CTL_IOCTL_PCM_PREFER_SUBDEVICE _IOW('U', 0x32, int)
#define SNDRV_CTL_IOCTL_POWER _IOWR('U', 0xd0, int)
#define SNDRV_CTL_IOCTL_POWER_STATE _IOR('U', 0xd1, int)
