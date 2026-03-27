#pragma once

#include "asound.h"

#include <dev/device.h>
#include <fs/vfs/vfs.h>
#include <libs/mutex.h>

#define SOUND_MAX_CARDS 8
#define SOUND_MAX_PCM_DEVICES 32
#define SOUND_MAX_PCM_SUBSTREAMS 2
#define SOUND_PCM_MMIO_PAGES 1

struct sound_pcm_substream;
typedef struct sound_pcm_substream sound_pcm_substream_t;

typedef struct sound_pcm_caps {
    uint64_t formats;
    uint64_t rates;
    uint32_t info;
    uint32_t min_rate;
    uint32_t max_rate;
    uint8_t channels_min;
    uint8_t channels_max;
    uint8_t sample_bits_min;
    uint8_t sample_bits_max;
    snd_pcm_format_t default_format;
    uint32_t default_rate;
    uint8_t default_channels;
    snd_pcm_uframes_t min_period_frames;
    snd_pcm_uframes_t max_period_frames;
    snd_pcm_uframes_t min_periods;
    snd_pcm_uframes_t max_periods;
    snd_pcm_uframes_t min_buffer_frames;
    snd_pcm_uframes_t max_buffer_frames;
    uint32_t fifo_size;
} sound_pcm_caps_t;

typedef struct sound_pcm_runtime {
    bool configured;
    bool prepared;
    bool running;
    bool draining;
    bool mmap_mode;
    snd_pcm_state_t state;
    snd_pcm_format_t format;
    snd_pcm_access_t access;
    snd_pcm_subformat_t subformat;
    uint32_t rate;
    uint32_t channels;
    uint32_t sample_bits;
    uint32_t frame_bits;
    uint32_t frame_bytes;
    snd_pcm_uframes_t period_size;
    snd_pcm_uframes_t periods;
    snd_pcm_uframes_t buffer_size;
    uint32_t period_bytes;
    uint32_t buffer_bytes;
    snd_pcm_uframes_t boundary;
    snd_pcm_uframes_t hw_ptr_base;
    snd_pcm_uframes_t appl_ptr;
    snd_pcm_uframes_t queued_frames;
    snd_pcm_uframes_t submitted_frames;
    snd_pcm_uframes_t avail_min;
    snd_pcm_uframes_t start_threshold;
    snd_pcm_uframes_t stop_threshold;
    snd_pcm_uframes_t avail_max;
    snd_pcm_sframes_t delay;
    uint64_t trigger_ns;
    uint64_t last_hw_ns;
    uint32_t tstamp_mode;
    uint32_t tstamp_type;
    void *dma_area;
    uint32_t dma_area_bytes;
    snd_pcm_mmap_status_t *mmap_status;
    uint32_t mmap_status_bytes;
    snd_pcm_mmap_control_t *mmap_control;
    uint32_t mmap_control_bytes;
} sound_pcm_runtime_t;

typedef struct sound_pcm_ops {
    int (*validate)(sound_pcm_substream_t *substream);
    int (*set_params)(sound_pcm_substream_t *substream);
    int (*prepare)(sound_pcm_substream_t *substream);
    int (*trigger)(sound_pcm_substream_t *substream, bool start);
    int (*drain)(sound_pcm_substream_t *substream);
    int (*free)(sound_pcm_substream_t *substream);
    int (*pump)(sound_pcm_substream_t *substream);
} sound_pcm_ops_t;

typedef struct sound_card {
    uint32_t index;
    char id[16];
    char driver[16];
    char name[32];
    char longname[80];
    char mixername[80];
    char components[128];
    uint64_t control_dev;
    int preferred_subdevice;
    int power_state;
    mutex_t lock;
} sound_card_t;

typedef struct sound_pcm_device {
    sound_card_t *card;
    uint32_t device_id;
    char id[64];
    char name[80];
    char subname[32];
    sound_pcm_substream_t *streams[SOUND_MAX_PCM_SUBSTREAMS];
} sound_pcm_device_t;

struct sound_pcm_substream {
    sound_pcm_device_t *pcm;
    uint32_t device_id;
    uint32_t stream;
    uint32_t subdevice;
    char path[32];
    char id[64];
    char name[80];
    char subname[32];
    uint64_t dev;
    vfs_node_t *node;
    bool node_registered;
    bool opened;
    sound_pcm_caps_t caps;
    sound_pcm_runtime_t runtime;
    sound_pcm_ops_t *ops;
    void *driver_data;
    mutex_t lock;
};

typedef struct sound_pcm_create_info {
    sound_card_t *card;
    uint32_t device_id;
    uint32_t stream;
    uint32_t subdevice;
    const char *id;
    const char *name;
    const char *subname;
    const sound_pcm_caps_t *caps;
    sound_pcm_ops_t *ops;
    void *driver_data;
    uint64_t minor;
} sound_pcm_create_info_t;

int sound_init(void);
sound_card_t *sound_card_create(const char *driver, const char *id,
                                const char *name, const char *longname,
                                const char *mixername, const char *components);
sound_pcm_substream_t *sound_pcm_create(const sound_pcm_create_info_t *info);
void sound_pcm_notify(sound_pcm_substream_t *substream);
sound_pcm_device_t *sound_find_pcm_device(sound_card_t *card, uint32_t device);
uint32_t sound_frames_to_bytes(const sound_pcm_runtime_t *runtime,
                               snd_pcm_uframes_t frames);
snd_pcm_uframes_t sound_bytes_to_frames(const sound_pcm_runtime_t *runtime,
                                        uint32_t bytes);
