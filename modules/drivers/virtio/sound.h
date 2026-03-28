#pragma once

#include "queue.h"
#include "virtio.h"

#include "../sound/sound.h"

#define VIRTIO_SOUND_F_CTLS (1ULL << 0)

typedef struct virtio_sound_config {
    uint32_t jacks;
    uint32_t streams;
    uint32_t chmaps;
    uint32_t controls;
} virtio_sound_config_t;

typedef struct virtio_snd_hdr {
    uint32_t code;
} virtio_snd_hdr_t;

typedef struct virtio_snd_query_info {
    virtio_snd_hdr_t hdr;
    uint32_t start_id;
    uint32_t count;
    uint32_t size;
} virtio_snd_query_info_t;

typedef struct virtio_snd_info {
    uint32_t hda_fn_nid;
} virtio_snd_info_t;

typedef struct virtio_snd_pcm_hdr {
    virtio_snd_hdr_t hdr;
    uint32_t stream_id;
} virtio_snd_pcm_hdr_t;

typedef struct virtio_snd_pcm_info {
    virtio_snd_info_t hdr;
    uint32_t features;
    uint64_t formats;
    uint64_t rates;
    uint8_t direction;
    uint8_t channels_min;
    uint8_t channels_max;
    uint8_t padding[5];
} virtio_snd_pcm_info_t;

typedef struct virtio_snd_pcm_set_params {
    virtio_snd_pcm_hdr_t hdr;
    uint32_t buffer_bytes;
    uint32_t period_bytes;
    uint32_t features;
    uint8_t channels;
    uint8_t format;
    uint8_t rate;
    uint8_t padding;
} virtio_snd_pcm_set_params_t;

typedef struct virtio_snd_pcm_xfer {
    uint32_t stream_id;
} virtio_snd_pcm_xfer_t;

typedef struct virtio_snd_pcm_status {
    uint32_t status;
    uint32_t latency_bytes;
} virtio_snd_pcm_status_t;

enum {
    VIRTIO_SND_VQ_CONTROL = 0,
    VIRTIO_SND_VQ_EVENT = 1,
    VIRTIO_SND_VQ_TX = 2,
    VIRTIO_SND_VQ_RX = 3,
};

enum {
    VIRTIO_SND_D_OUTPUT = 0,
    VIRTIO_SND_D_INPUT = 1,
};

enum {
    VIRTIO_SND_R_PCM_INFO = 0x0100,
    VIRTIO_SND_R_PCM_SET_PARAMS,
    VIRTIO_SND_R_PCM_PREPARE,
    VIRTIO_SND_R_PCM_RELEASE,
    VIRTIO_SND_R_PCM_START,
    VIRTIO_SND_R_PCM_STOP,
};

enum {
    VIRTIO_SND_S_OK = 0x8000,
    VIRTIO_SND_S_BAD_MSG,
    VIRTIO_SND_S_NOT_SUPP,
    VIRTIO_SND_S_IO_ERR,
};

enum {
    VIRTIO_SND_PCM_FMT_S8 = 3,
    VIRTIO_SND_PCM_FMT_U8 = 4,
    VIRTIO_SND_PCM_FMT_S16 = 5,
    VIRTIO_SND_PCM_FMT_U16 = 6,
    VIRTIO_SND_PCM_FMT_S24_3 = 11,
    VIRTIO_SND_PCM_FMT_U24_3 = 12,
    VIRTIO_SND_PCM_FMT_S24 = 15,
    VIRTIO_SND_PCM_FMT_U24 = 16,
    VIRTIO_SND_PCM_FMT_S32 = 17,
    VIRTIO_SND_PCM_FMT_U32 = 18,
    VIRTIO_SND_PCM_FMT_FLOAT = 19,
    VIRTIO_SND_PCM_FMT_FLOAT64 = 20,
};

enum {
    VIRTIO_SND_PCM_RATE_5512 = 0,
    VIRTIO_SND_PCM_RATE_8000,
    VIRTIO_SND_PCM_RATE_11025,
    VIRTIO_SND_PCM_RATE_16000,
    VIRTIO_SND_PCM_RATE_22050,
    VIRTIO_SND_PCM_RATE_32000,
    VIRTIO_SND_PCM_RATE_44100,
    VIRTIO_SND_PCM_RATE_48000,
    VIRTIO_SND_PCM_RATE_64000,
    VIRTIO_SND_PCM_RATE_88200,
    VIRTIO_SND_PCM_RATE_96000,
    VIRTIO_SND_PCM_RATE_176400,
    VIRTIO_SND_PCM_RATE_192000,
    VIRTIO_SND_PCM_RATE_384000,
};

int virtio_sound_init(virtio_driver_t *driver);
