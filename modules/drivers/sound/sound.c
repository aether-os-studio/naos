#include "sound.h"

#include <mod/dlinker.h>
#include <task/task.h>

static sound_card_t *sound_cards[SOUND_MAX_CARDS];
static sound_pcm_device_t
    *sound_pcm_devices[SOUND_MAX_CARDS][SOUND_MAX_PCM_DEVICES];
static uint32_t sound_cards_count = 0;
static spinlock_t sound_registry_lock = SPIN_INIT;
static bool sound_ready = false;

static uint32_t sound_pcm_bits_to_bytes(uint32_t bits) {
    return (bits + 7U) / 8U;
}

static void sound_mask_clear(snd_mask_t *mask) {
    memset(mask, 0, sizeof(*mask));
}

static void sound_mask_set_bit(snd_mask_t *mask, uint32_t bit) {
    if (!mask || bit >= SNDRV_MASK_MAX) {
        return;
    }
    mask->bits[bit / 32] |= (1U << (bit % 32));
}

static bool sound_mask_test_bit(const snd_mask_t *mask, uint32_t bit) {
    if (!mask || bit >= SNDRV_MASK_MAX) {
        return false;
    }
    return !!(mask->bits[bit / 32] & (1U << (bit % 32)));
}

static bool sound_mask_empty(const snd_mask_t *mask) {
    if (!mask) {
        return true;
    }
    for (size_t i = 0; i < sizeof(mask->bits) / sizeof(mask->bits[0]); i++) {
        if (mask->bits[i]) {
            return false;
        }
    }
    return true;
}

static void sound_mask_set_only(snd_mask_t *mask, uint32_t bit) {
    sound_mask_clear(mask);
    sound_mask_set_bit(mask, bit);
}

static void sound_mask_copy(snd_mask_t *dst, const snd_mask_t *src) {
    if (!dst || !src) {
        return;
    }
    memcpy(dst, src, sizeof(*dst));
}

static bool sound_mask_intersect(snd_mask_t *mask,
                                 const snd_mask_t *supported) {
    if (!mask || !supported) {
        return false;
    }

    if (sound_mask_empty(mask)) {
        sound_mask_copy(mask, supported);
        return !sound_mask_empty(mask);
    }

    for (size_t i = 0; i < sizeof(mask->bits) / sizeof(mask->bits[0]); i++) {
        mask->bits[i] &= supported->bits[i];
    }
    return !sound_mask_empty(mask);
}

static snd_interval_t *sound_hw_param_interval(snd_pcm_hw_params_t *params,
                                               uint32_t which) {
    return &params->intervals[which - SNDRV_PCM_HW_PARAM_FIRST_INTERVAL];
}

static snd_mask_t *sound_hw_param_mask(snd_pcm_hw_params_t *params,
                                       uint32_t which) {
    return &params->masks[which - SNDRV_PCM_HW_PARAM_FIRST_MASK];
}

static void sound_interval_set_fixed(snd_interval_t *it, uint32_t value) {
    if (!it) {
        return;
    }
    it->min = value;
    it->max = value;
    it->openmin = 0;
    it->openmax = 0;
    it->integer = 1;
    it->empty = 0;
}

static void sound_interval_set_range(snd_interval_t *it, uint32_t min,
                                     uint32_t max, bool integer) {
    if (!it) {
        return;
    }
    it->min = min;
    it->max = max;
    it->openmin = 0;
    it->openmax = 0;
    it->integer = integer ? 1U : 0U;
    it->empty = min > max;
}

static bool sound_interval_unset(const snd_interval_t *it) {
    if (!it) {
        return true;
    }
    return !it->empty && it->min == 0 && it->max == 0 && !it->openmin &&
           !it->openmax && !it->integer;
}

static bool sound_interval_intersect_range(snd_interval_t *it, uint32_t min,
                                           uint32_t max, bool integer) {
    if (!it) {
        return false;
    }

    if (sound_interval_unset(it)) {
        sound_interval_set_range(it, min, max, integer);
        return !it->empty;
    }

    uint32_t cur_max = it->max ? it->max : UINT32_MAX;
    uint32_t new_min = MAX(it->min, min);
    uint32_t new_max = MIN(cur_max, max);
    sound_interval_set_range(it, new_min, new_max, integer || it->integer);
    return !it->empty;
}

static uint32_t sound_interval_pick(const snd_interval_t *it, uint32_t fallback,
                                    uint32_t clamp_min, uint32_t clamp_max) {
    if (!it || it->empty) {
        return fallback;
    }

    uint32_t min = MAX(it->min, clamp_min);
    uint32_t max = MIN(it->max ? it->max : clamp_max, clamp_max);
    if (min > max) {
        return fallback;
    }
    if (fallback < min) {
        return min;
    }
    if (fallback > max) {
        return max;
    }
    return fallback;
}

static uint32_t sound_pick_access(const sound_pcm_caps_t *caps,
                                  snd_pcm_hw_params_t *params) {
    snd_mask_t *mask = sound_hw_param_mask(params, SNDRV_PCM_HW_PARAM_ACCESS);
    if (sound_mask_test_bit(mask, SNDRV_PCM_ACCESS_RW_INTERLEAVED)) {
        return SNDRV_PCM_ACCESS_RW_INTERLEAVED;
    }
    if ((caps->info & SNDRV_PCM_INFO_MMAP) &&
        sound_mask_test_bit(mask, SNDRV_PCM_ACCESS_MMAP_INTERLEAVED)) {
        return SNDRV_PCM_ACCESS_MMAP_INTERLEAVED;
    }
    return SNDRV_PCM_ACCESS_RW_INTERLEAVED;
}

static snd_pcm_format_t sound_pick_format(const sound_pcm_caps_t *caps,
                                          snd_pcm_hw_params_t *params) {
    snd_mask_t *mask = sound_hw_param_mask(params, SNDRV_PCM_HW_PARAM_FORMAT);
    if (sound_mask_empty(mask) ||
        sound_mask_test_bit(mask, (uint32_t)caps->default_format)) {
        return caps->default_format;
    }

    for (uint32_t fmt = 0; fmt < 64; fmt++) {
        if ((caps->formats & (1ULL << fmt)) && sound_mask_test_bit(mask, fmt)) {
            return (snd_pcm_format_t)fmt;
        }
    }

    for (uint32_t fmt = 0; fmt < 64; fmt++) {
        if (caps->formats & (1ULL << fmt)) {
            return (snd_pcm_format_t)fmt;
        }
    }

    return caps->default_format;
}

static uint32_t sound_rate_supported_mask(const sound_pcm_caps_t *caps,
                                          uint32_t rate) {
    static const uint32_t rates[] = {5512,  8000,   11025,  16000, 22050,
                                     32000, 44100,  48000,  64000, 88200,
                                     96000, 176400, 192000, 384000};

    for (uint32_t i = 0; i < sizeof(rates) / sizeof(rates[0]); i++) {
        if (rates[i] == rate) {
            return (caps->rates & (1ULL << i)) != 0;
        }
    }
    return 0;
}

static uint32_t sound_pick_rate(const sound_pcm_caps_t *caps,
                                snd_pcm_hw_params_t *params) {
    snd_interval_t *it =
        sound_hw_param_interval(params, SNDRV_PCM_HW_PARAM_RATE);
    uint32_t rate = sound_interval_pick(it, caps->default_rate, caps->min_rate,
                                        caps->max_rate);
    if (sound_rate_supported_mask(caps, rate)) {
        return rate;
    }

    static const uint32_t rates[] = {48000,  44100,  32000, 96000, 88200,
                                     192000, 176400, 64000, 22050, 16000,
                                     11025,  8000,   5512,  384000};
    for (uint32_t i = 0; i < sizeof(rates) / sizeof(rates[0]); i++) {
        if (rates[i] >= it->min && rates[i] <= it->max &&
            sound_rate_supported_mask(caps, rates[i])) {
            return rates[i];
        }
    }

    return caps->default_rate;
}

static uint32_t sound_pcm_format_bits(snd_pcm_format_t format) {
    switch (format) {
    case SNDRV_PCM_FORMAT_S8:
    case SNDRV_PCM_FORMAT_U8:
        return 8;
    case SNDRV_PCM_FORMAT_S16_LE:
    case SNDRV_PCM_FORMAT_U16_LE:
        return 16;
    case SNDRV_PCM_FORMAT_S24_3LE:
    case SNDRV_PCM_FORMAT_U24_3LE:
    case SNDRV_PCM_FORMAT_S24_LE:
    case SNDRV_PCM_FORMAT_U24_LE:
        return 24;
    case SNDRV_PCM_FORMAT_S32_LE:
    case SNDRV_PCM_FORMAT_U32_LE:
    case SNDRV_PCM_FORMAT_FLOAT_LE:
        return 32;
    case SNDRV_PCM_FORMAT_FLOAT64_LE:
        return 64;
    default:
        return 16;
    }
}

static uint32_t sound_pick_channels(const sound_pcm_caps_t *caps,
                                    snd_pcm_hw_params_t *params) {
    snd_interval_t *it =
        sound_hw_param_interval(params, SNDRV_PCM_HW_PARAM_CHANNELS);
    return sound_interval_pick(it, caps->default_channels, caps->channels_min,
                               caps->channels_max);
}

static snd_pcm_uframes_t sound_pick_period_size(const sound_pcm_caps_t *caps,
                                                snd_pcm_hw_params_t *params) {
    snd_interval_t *it =
        sound_hw_param_interval(params, SNDRV_PCM_HW_PARAM_PERIOD_SIZE);
    snd_pcm_uframes_t fallback = caps->min_period_frames;
    if (fallback < 256) {
        fallback = 256;
    }
    return sound_interval_pick(it, fallback, caps->min_period_frames,
                               caps->max_period_frames);
}

static snd_pcm_uframes_t sound_pick_periods(const sound_pcm_caps_t *caps,
                                            snd_pcm_hw_params_t *params) {
    snd_interval_t *it =
        sound_hw_param_interval(params, SNDRV_PCM_HW_PARAM_PERIODS);
    snd_pcm_uframes_t fallback = 4;
    if (fallback < caps->min_periods) {
        fallback = caps->min_periods;
    }
    if (fallback > caps->max_periods) {
        fallback = caps->max_periods;
    }
    return sound_interval_pick(it, fallback, caps->min_periods,
                               caps->max_periods);
}

uint32_t sound_frames_to_bytes(const sound_pcm_runtime_t *runtime,
                               snd_pcm_uframes_t frames) {
    return runtime ? (uint32_t)(frames * runtime->frame_bytes) : 0;
}

snd_pcm_uframes_t sound_bytes_to_frames(const sound_pcm_runtime_t *runtime,
                                        uint32_t bytes) {
    return (runtime && runtime->frame_bytes)
               ? (snd_pcm_uframes_t)(bytes / runtime->frame_bytes)
               : 0;
}

static void sound_runtime_update_mmap(sound_pcm_substream_t *substream) {
    sound_pcm_runtime_t *runtime = &substream->runtime;

    if (!runtime->mmap_status || !runtime->mmap_control) {
        return;
    }

    runtime->mmap_status->state = runtime->state;
    runtime->mmap_status->hw_ptr = runtime->hw_ptr_base;
    runtime->mmap_status->suspended_state = SNDRV_PCM_STATE_OPEN;
    runtime->mmap_status->tstamp.tv_sec = nano_time() / 1000000000ULL;
    runtime->mmap_status->tstamp.tv_nsec = nano_time() % 1000000000ULL;
    runtime->mmap_status->audio_tstamp = runtime->mmap_status->tstamp;
    runtime->mmap_control->appl_ptr = runtime->appl_ptr;
    runtime->mmap_control->avail_min = runtime->avail_min;
}

static snd_pcm_uframes_t
sound_runtime_buffered(const sound_pcm_runtime_t *runtime) {
    if (!runtime || !runtime->buffer_size ||
        runtime->appl_ptr < runtime->hw_ptr_base) {
        return 0;
    }

    snd_pcm_uframes_t used = runtime->appl_ptr - runtime->hw_ptr_base;
    if (used > runtime->buffer_size) {
        return runtime->buffer_size;
    }
    return used;
}

static snd_pcm_uframes_t
sound_runtime_avail(const sound_pcm_runtime_t *runtime) {
    if (!runtime || !runtime->buffer_size) {
        return 0;
    }
    snd_pcm_uframes_t used = sound_runtime_buffered(runtime);
    return runtime->buffer_size > used ? runtime->buffer_size - used : 0;
}

static void sound_runtime_set_state(sound_pcm_substream_t *substream,
                                    snd_pcm_state_t state) {
    substream->runtime.state = state;
    sound_runtime_update_mmap(substream);
}

static void sound_runtime_release(sound_pcm_substream_t *substream) {
    sound_pcm_runtime_t *runtime = &substream->runtime;

    if (runtime->dma_area) {
        free_frames_bytes(runtime->dma_area, runtime->dma_area_bytes);
        runtime->dma_area = NULL;
        runtime->dma_area_bytes = 0;
    }
    if (runtime->mmap_status) {
        free_frames_bytes(runtime->mmap_status, runtime->mmap_status_bytes);
        runtime->mmap_status = NULL;
        runtime->mmap_status_bytes = 0;
    }
    if (runtime->mmap_control) {
        free_frames_bytes(runtime->mmap_control, runtime->mmap_control_bytes);
        runtime->mmap_control = NULL;
        runtime->mmap_control_bytes = 0;
    }
}

static int
sound_runtime_allocate_control_pages(sound_pcm_substream_t *substream) {
    sound_pcm_runtime_t *runtime = &substream->runtime;
    uint64_t status_bytes = PAGE_SIZE * SOUND_PCM_MMIO_PAGES;
    uint64_t control_bytes = PAGE_SIZE * SOUND_PCM_MMIO_PAGES;

    if (runtime->mmap_status && runtime->mmap_status_bytes != status_bytes) {
        free_frames_bytes(runtime->mmap_status, runtime->mmap_status_bytes);
        runtime->mmap_status = NULL;
        runtime->mmap_status_bytes = 0;
    }
    if (!runtime->mmap_status) {
        runtime->mmap_status = alloc_frames_bytes(status_bytes);
        if (!runtime->mmap_status) {
            return -ENOMEM;
        }
        runtime->mmap_status_bytes = status_bytes;
        memset(runtime->mmap_status, 0, status_bytes);
    }

    if (runtime->mmap_control && runtime->mmap_control_bytes != control_bytes) {
        free_frames_bytes(runtime->mmap_control, runtime->mmap_control_bytes);
        runtime->mmap_control = NULL;
        runtime->mmap_control_bytes = 0;
    }
    if (!runtime->mmap_control) {
        runtime->mmap_control = alloc_frames_bytes(control_bytes);
        if (!runtime->mmap_control) {
            return -ENOMEM;
        }
        runtime->mmap_control_bytes = control_bytes;
        memset(runtime->mmap_control, 0, control_bytes);
    }

    if (!runtime->avail_min) {
        runtime->avail_min = 1;
    }
    sound_runtime_update_mmap(substream);
    return 0;
}

static int sound_runtime_allocate(sound_pcm_substream_t *substream) {
    sound_pcm_runtime_t *runtime = &substream->runtime;

    if (!runtime->buffer_bytes) {
        return -EINVAL;
    }

    if (runtime->dma_area && runtime->dma_area_bytes != runtime->buffer_bytes) {
        free_frames_bytes(runtime->dma_area, runtime->dma_area_bytes);
        runtime->dma_area = NULL;
        runtime->dma_area_bytes = 0;
    }
    if (!runtime->dma_area) {
        runtime->dma_area = alloc_frames_bytes(runtime->buffer_bytes);
        if (!runtime->dma_area) {
            return -ENOMEM;
        }
        runtime->dma_area_bytes = runtime->buffer_bytes;
        memset(runtime->dma_area, 0, runtime->buffer_bytes);
    }

    if (sound_runtime_allocate_control_pages(substream) < 0) {
        return -ENOMEM;
    }

    return 0;
}

static void sound_runtime_reset(sound_pcm_substream_t *substream) {
    sound_pcm_runtime_t *runtime = &substream->runtime;
    runtime->prepared = false;
    runtime->running = false;
    runtime->draining = false;
    runtime->appl_ptr = 0;
    runtime->hw_ptr_base = 0;
    runtime->queued_frames = 0;
    runtime->submitted_frames = 0;
    runtime->avail_max = runtime->buffer_size;
    runtime->delay = 0;
    runtime->trigger_ns = 0;
    runtime->last_hw_ns = 0;
    if (runtime->dma_area && runtime->buffer_bytes) {
        memset(runtime->dma_area, 0, runtime->buffer_bytes);
    }
    sound_runtime_set_state(substream, runtime->configured
                                           ? SNDRV_PCM_STATE_SETUP
                                           : SNDRV_PCM_STATE_OPEN);
}

static sound_pcm_substream_t *sound_dev_to_substream(void *dev) {
    return (sound_pcm_substream_t *)dev;
}

static sound_card_t *sound_dev_to_card(void *dev) {
    return (sound_card_t *)dev;
}

static int sound_pcm_backend_validate(sound_pcm_substream_t *substream) {
    if (!substream) {
        return -ENODEV;
    }
    if (!substream->ops) {
        return 0;
    }
    if ((substream->ops->set_params || substream->ops->prepare ||
         substream->ops->trigger || substream->ops->drain ||
         substream->ops->free || substream->ops->pump) &&
        !substream->driver_data) {
        return -ENODEV;
    }
    if (substream->ops->validate) {
        return substream->ops->validate(substream);
    }
    return 0;
}

static void sound_fill_pcm_info(sound_pcm_substream_t *substream,
                                snd_pcm_info_t *info) {
    memset(info, 0, sizeof(*info));
    info->device = substream->device_id;
    info->subdevice = substream->subdevice;
    info->stream = (int)substream->stream;
    info->card = (int)substream->pcm->card->index;
    strncpy((char *)info->id, substream->id, sizeof(info->id) - 1);
    strncpy((char *)info->name, substream->name, sizeof(info->name) - 1);
    strncpy((char *)info->subname, substream->subname,
            sizeof(info->subname) - 1);
    info->dev_class = 0;
    info->dev_subclass = 0;
    info->subdevices_count = 1;
    info->subdevices_avail = substream->opened ? 0U : 1U;
}

static int sound_hw_params_apply(sound_pcm_substream_t *substream,
                                 snd_pcm_hw_params_t *params) {
    sound_pcm_runtime_t *runtime = &substream->runtime;
    const sound_pcm_caps_t *caps = &substream->caps;
    snd_pcm_access_t access = (snd_pcm_access_t)sound_pick_access(caps, params);
    snd_pcm_format_t format = sound_pick_format(caps, params);
    uint32_t rate = sound_pick_rate(caps, params);
    uint32_t channels = sound_pick_channels(caps, params);
    uint32_t sample_bits = sound_pcm_format_bits(format);
    uint32_t frame_bits = sample_bits * channels;
    uint32_t frame_bytes = sound_pcm_bits_to_bytes(frame_bits);
    snd_pcm_uframes_t period_size = sound_pick_period_size(caps, params);
    snd_pcm_uframes_t periods = sound_pick_periods(caps, params);
    snd_pcm_uframes_t buffer_size = period_size * periods;
    uint32_t period_bytes = (uint32_t)(period_size * frame_bytes);
    uint32_t buffer_bytes = (uint32_t)(buffer_size * frame_bytes);

    if (!frame_bytes || !period_size || !periods || !buffer_size ||
        !period_bytes || !buffer_bytes) {
        return -EINVAL;
    }

    int backend_ret = sound_pcm_backend_validate(substream);
    if (backend_ret < 0) {
        return backend_ret;
    }

    if (runtime->configured && substream->ops && substream->ops->free) {
        substream->ops->free(substream);
    }

    runtime->access = access;
    runtime->format = format;
    runtime->subformat = SNDRV_PCM_SUBFORMAT_STD;
    runtime->rate = rate;
    runtime->channels = channels;
    runtime->sample_bits = sample_bits;
    runtime->frame_bits = frame_bits;
    runtime->frame_bytes = frame_bytes;
    runtime->period_size = period_size;
    runtime->periods = periods;
    runtime->buffer_size = buffer_size;
    runtime->period_bytes = period_bytes;
    runtime->buffer_bytes = buffer_bytes;
    runtime->boundary = buffer_size * 4;
    runtime->avail_min = period_size;
    runtime->start_threshold = period_size;
    runtime->stop_threshold = buffer_size;
    runtime->configured = false;
    runtime->mmap_mode = runtime->access == SNDRV_PCM_ACCESS_MMAP_INTERLEAVED;

    if (sound_runtime_allocate(substream) != 0) {
        sound_runtime_release(substream);
        return -ENOMEM;
    }

    if (substream->ops && substream->ops->set_params) {
        int ret = substream->ops->set_params(substream);
        if (ret < 0) {
            sound_runtime_release(substream);
            runtime->configured = false;
            return ret;
        }
    }

    runtime->configured = true;

    sound_mask_set_only(sound_hw_param_mask(params, SNDRV_PCM_HW_PARAM_ACCESS),
                        runtime->access);
    sound_mask_set_only(sound_hw_param_mask(params, SNDRV_PCM_HW_PARAM_FORMAT),
                        (uint32_t)runtime->format);
    sound_mask_set_only(
        sound_hw_param_mask(params, SNDRV_PCM_HW_PARAM_SUBFORMAT),
        (uint32_t)runtime->subformat);
    sound_interval_set_fixed(
        sound_hw_param_interval(params, SNDRV_PCM_HW_PARAM_SAMPLE_BITS),
        runtime->sample_bits);
    sound_interval_set_fixed(
        sound_hw_param_interval(params, SNDRV_PCM_HW_PARAM_FRAME_BITS),
        runtime->frame_bits);
    sound_interval_set_fixed(
        sound_hw_param_interval(params, SNDRV_PCM_HW_PARAM_CHANNELS),
        runtime->channels);
    sound_interval_set_fixed(
        sound_hw_param_interval(params, SNDRV_PCM_HW_PARAM_RATE),
        runtime->rate);
    sound_interval_set_fixed(
        sound_hw_param_interval(params, SNDRV_PCM_HW_PARAM_PERIOD_SIZE),
        runtime->period_size);
    sound_interval_set_fixed(
        sound_hw_param_interval(params, SNDRV_PCM_HW_PARAM_PERIOD_BYTES),
        runtime->period_bytes);
    sound_interval_set_fixed(
        sound_hw_param_interval(params, SNDRV_PCM_HW_PARAM_PERIODS),
        runtime->periods);
    sound_interval_set_fixed(
        sound_hw_param_interval(params, SNDRV_PCM_HW_PARAM_BUFFER_SIZE),
        runtime->buffer_size);
    sound_interval_set_fixed(
        sound_hw_param_interval(params, SNDRV_PCM_HW_PARAM_BUFFER_BYTES),
        runtime->buffer_bytes);
    sound_interval_set_fixed(
        sound_hw_param_interval(params, SNDRV_PCM_HW_PARAM_PERIOD_TIME),
        runtime->rate ? (runtime->period_size * 1000000U) / runtime->rate : 0);
    sound_interval_set_fixed(
        sound_hw_param_interval(params, SNDRV_PCM_HW_PARAM_BUFFER_TIME),
        runtime->rate ? (runtime->buffer_size * 1000000U) / runtime->rate : 0);
    sound_interval_set_fixed(
        sound_hw_param_interval(params, SNDRV_PCM_HW_PARAM_TICK_TIME), 0);

    params->info = caps->info;
    params->msbits = runtime->sample_bits;
    params->rate_num = runtime->rate;
    params->rate_den = 1;
    params->fifo_size = caps->fifo_size;

    sound_runtime_reset(substream);
    return 0;
}

static int sound_hw_refine_fill_defaults(sound_pcm_substream_t *substream,
                                         snd_pcm_hw_params_t *params) {
    const sound_pcm_caps_t *caps = &substream->caps;
    snd_mask_t supported_access;
    snd_mask_t supported_formats;
    snd_mask_t supported_subformats;

    memset(&supported_access, 0, sizeof(supported_access));
    memset(&supported_formats, 0, sizeof(supported_formats));
    memset(&supported_subformats, 0, sizeof(supported_subformats));

    sound_mask_set_bit(&supported_access, SNDRV_PCM_ACCESS_RW_INTERLEAVED);
    if (caps->info & SNDRV_PCM_INFO_MMAP) {
        sound_mask_set_bit(&supported_access,
                           SNDRV_PCM_ACCESS_MMAP_INTERLEAVED);
    }
    for (uint32_t fmt = 0; fmt < 64; fmt++) {
        if (caps->formats & (1ULL << fmt)) {
            sound_mask_set_bit(&supported_formats, fmt);
        }
    }
    sound_mask_set_only(&supported_subformats, SNDRV_PCM_SUBFORMAT_STD);

    if (!sound_mask_intersect(
            sound_hw_param_mask(params, SNDRV_PCM_HW_PARAM_ACCESS),
            &supported_access)) {
        return -EINVAL;
    }
    if (!sound_mask_intersect(
            sound_hw_param_mask(params, SNDRV_PCM_HW_PARAM_FORMAT),
            &supported_formats)) {
        return -EINVAL;
    }
    if (!sound_mask_intersect(
            sound_hw_param_mask(params, SNDRV_PCM_HW_PARAM_SUBFORMAT),
            &supported_subformats)) {
        return -EINVAL;
    }

    if (!sound_interval_intersect_range(
            sound_hw_param_interval(params, SNDRV_PCM_HW_PARAM_SAMPLE_BITS),
            caps->sample_bits_min, caps->sample_bits_max, true) ||
        !sound_interval_intersect_range(
            sound_hw_param_interval(params, SNDRV_PCM_HW_PARAM_FRAME_BITS),
            caps->sample_bits_min * caps->channels_min,
            caps->sample_bits_max * caps->channels_max, true) ||
        !sound_interval_intersect_range(
            sound_hw_param_interval(params, SNDRV_PCM_HW_PARAM_CHANNELS),
            caps->channels_min, caps->channels_max, true) ||
        !sound_interval_intersect_range(
            sound_hw_param_interval(params, SNDRV_PCM_HW_PARAM_RATE),
            caps->min_rate, caps->max_rate, true) ||
        !sound_interval_intersect_range(
            sound_hw_param_interval(params, SNDRV_PCM_HW_PARAM_PERIOD_SIZE),
            caps->min_period_frames, caps->max_period_frames, true) ||
        !sound_interval_intersect_range(
            sound_hw_param_interval(params, SNDRV_PCM_HW_PARAM_PERIODS),
            caps->min_periods, caps->max_periods, true) ||
        !sound_interval_intersect_range(
            sound_hw_param_interval(params, SNDRV_PCM_HW_PARAM_BUFFER_SIZE),
            caps->min_buffer_frames, caps->max_buffer_frames, true) ||
        !sound_interval_intersect_range(
            sound_hw_param_interval(params, SNDRV_PCM_HW_PARAM_PERIOD_BYTES),
            caps->min_period_frames *
                sound_pcm_bits_to_bytes(caps->sample_bits_min) *
                caps->channels_min,
            caps->max_period_frames *
                sound_pcm_bits_to_bytes(caps->sample_bits_max) *
                caps->channels_max,
            true) ||
        !sound_interval_intersect_range(
            sound_hw_param_interval(params, SNDRV_PCM_HW_PARAM_BUFFER_BYTES),
            caps->min_buffer_frames *
                sound_pcm_bits_to_bytes(caps->sample_bits_min) *
                caps->channels_min,
            caps->max_buffer_frames *
                sound_pcm_bits_to_bytes(caps->sample_bits_max) *
                caps->channels_max,
            true)) {
        return -EINVAL;
    }

    params->info = caps->info;
    params->fifo_size = caps->fifo_size;
    return 0;
}

static int sound_pcm_open(void *dev, void *arg) {
    sound_pcm_substream_t *substream = sound_dev_to_substream(dev);
    (void)arg;
    mutex_lock(&substream->lock);
    if (substream->opened) {
        mutex_unlock(&substream->lock);
        return -EBUSY;
    }
    substream->opened = true;
    if (sound_runtime_allocate_control_pages(substream) < 0) {
        substream->opened = false;
        mutex_unlock(&substream->lock);
        return -ENOMEM;
    }
    sound_runtime_reset(substream);
    mutex_unlock(&substream->lock);
    return 0;
}

static int sound_pcm_close(void *dev) {
    sound_pcm_substream_t *substream = sound_dev_to_substream(dev);
    mutex_lock(&substream->lock);
    if (substream->ops && substream->ops->free &&
        sound_pcm_backend_validate(substream) == 0) {
        substream->ops->free(substream);
    }
    sound_runtime_release(substream);
    substream->runtime.configured = false;
    substream->opened = false;
    sound_runtime_reset(substream);
    mutex_unlock(&substream->lock);
    return 0;
}

static int sound_pcm_status_fill(sound_pcm_substream_t *substream,
                                 snd_pcm_status_t *status) {
    sound_pcm_runtime_t *runtime = &substream->runtime;
    if (substream->ops && substream->ops->pump &&
        sound_pcm_backend_validate(substream) == 0) {
        substream->ops->pump(substream);
    }

    memset(status, 0, sizeof(*status));
    status->state = runtime->state;
    status->trigger_tstamp.tv_sec = runtime->trigger_ns / 1000000000ULL;
    status->trigger_tstamp.tv_nsec = runtime->trigger_ns % 1000000000ULL;
    status->tstamp.tv_sec = nano_time() / 1000000000ULL;
    status->tstamp.tv_nsec = nano_time() % 1000000000ULL;
    status->appl_ptr = runtime->appl_ptr;
    status->hw_ptr = runtime->hw_ptr_base;
    status->avail = sound_runtime_avail(runtime);
    status->delay = runtime->delay;
    status->avail_max = runtime->avail_max;
    status->suspended_state = SNDRV_PCM_STATE_OPEN;
    status->audio_tstamp_data = SNDRV_PCM_AUDIO_TSTAMP_TYPE_DEFAULT;
    status->audio_tstamp = status->tstamp;
    status->driver_tstamp = status->tstamp;
    runtime->avail_max = status->avail;
    sound_runtime_update_mmap(substream);
    return 0;
}

static int sound_pcm_sync_ptr_apply(sound_pcm_substream_t *substream,
                                    snd_pcm_sync_ptr_t *sync) {
    sound_pcm_runtime_t *runtime = &substream->runtime;

    if (!runtime->mmap_status || !runtime->mmap_control) {
        int ret = sound_runtime_allocate_control_pages(substream);
        if (ret < 0) {
            return ret;
        }
    }

    if (!(sync->flags & SNDRV_PCM_SYNC_PTR_APPL)) {
        runtime->appl_ptr = sync->c.control.appl_ptr;
        runtime->avail_min = sync->c.control.avail_min;
        runtime->mmap_mode = true;
    }

    if (runtime->configured && substream->ops && substream->ops->pump) {
        int ret = sound_pcm_backend_validate(substream);
        if (ret < 0) {
            return ret;
        }
        substream->ops->pump(substream);
    }

    runtime->mmap_control->appl_ptr = runtime->appl_ptr;
    runtime->mmap_control->avail_min = runtime->avail_min;
    sync->s.status = *runtime->mmap_status;
    sync->c.control = *runtime->mmap_control;
    return 0;
}

static int sound_pcm_write_frames_locked(sound_pcm_substream_t *substream,
                                         snd_xferi_t *xfer) {
    sound_pcm_runtime_t *runtime = &substream->runtime;
    snd_pcm_uframes_t avail = sound_runtime_avail(runtime);
    snd_pcm_uframes_t frames = MIN((snd_pcm_uframes_t)xfer->frames, avail);
    uint32_t bytes = sound_frames_to_bytes(runtime, frames);
    uint32_t offset = sound_frames_to_bytes(runtime, runtime->appl_ptr %
                                                         runtime->buffer_size);
    uint32_t first = MIN(bytes, runtime->buffer_bytes - offset);

    if (!runtime->configured || !runtime->dma_area) {
        return -EINVAL;
    }
    if (frames == 0) {
        xfer->result = 0;
        return 0;
    }
    if (!xfer->buf || copy_from_user((uint8_t *)runtime->dma_area + offset,
                                     xfer->buf, first)) {
        return -EFAULT;
    }
    if (bytes > first &&
        copy_from_user(runtime->dma_area, (uint8_t *)xfer->buf + first,
                       bytes - first)) {
        return -EFAULT;
    }

    runtime->appl_ptr += frames;
    runtime->queued_frames += frames;
    runtime->avail_max = MAX(runtime->avail_max, sound_runtime_avail(runtime));
    sound_runtime_update_mmap(substream);

    if (runtime->state == SNDRV_PCM_STATE_PREPARED &&
        runtime->appl_ptr >= runtime->start_threshold) {
        runtime->running = true;
        runtime->state = SNDRV_PCM_STATE_RUNNING;
        runtime->trigger_ns = nano_time();
        if (substream->ops && substream->ops->trigger &&
            sound_pcm_backend_validate(substream) == 0) {
            substream->ops->trigger(substream, true);
        }
    }
    if (substream->ops && substream->ops->pump &&
        sound_pcm_backend_validate(substream) == 0) {
        substream->ops->pump(substream);
    }

    xfer->result = frames;
    return 0;
}

static ssize_t sound_pcm_ioctl(void *dev, int cmd, void *args, fd_t *fd) {
    sound_pcm_substream_t *substream = sound_dev_to_substream(dev);
    sound_pcm_runtime_t *runtime = &substream->runtime;
    ssize_t ret = -ENOTTY;
    (void)fd;

    mutex_lock(&substream->lock);

    switch ((uint32_t)cmd) {
    case SNDRV_PCM_IOCTL_PVERSION:
        ret =
            !args || copy_to_user(args, &(int){SNDRV_PCM_VERSION}, sizeof(int))
                ? -EFAULT
                : 0;
        break;
    case SNDRV_PCM_IOCTL_INFO: {
        snd_pcm_info_t info;
        sound_fill_pcm_info(substream, &info);
        ret = !args || copy_to_user(args, &info, sizeof(info)) ? -EFAULT : 0;
        break;
    }
    case SNDRV_PCM_IOCTL_TSTAMP:
    case SNDRV_PCM_IOCTL_TTSTAMP:
    case SNDRV_PCM_IOCTL_USER_PVERSION:
        ret = 0;
        break;
    case SNDRV_PCM_IOCTL_HW_REFINE: {
        snd_pcm_hw_params_t params;
        if (!args || copy_from_user(&params, args, sizeof(params))) {
            ret = -EFAULT;
            break;
        }
        ret = sound_hw_refine_fill_defaults(substream, &params);
        if (ret == 0 && copy_to_user(args, &params, sizeof(params))) {
            ret = -EFAULT;
        }
        break;
    }
    case SNDRV_PCM_IOCTL_HW_PARAMS: {
        snd_pcm_hw_params_t params;
        if (!args || copy_from_user(&params, args, sizeof(params))) {
            ret = -EFAULT;
            break;
        }
        ret = sound_hw_params_apply(substream, &params);
        if (ret == 0 && copy_to_user(args, &params, sizeof(params))) {
            ret = -EFAULT;
        }
        break;
    }
    case SNDRV_PCM_IOCTL_HW_FREE:
        if (runtime->configured && substream->ops && substream->ops->free) {
            int backend_ret = sound_pcm_backend_validate(substream);
            if (backend_ret == 0) {
                substream->ops->free(substream);
            }
        }
        sound_runtime_release(substream);
        sound_runtime_reset(substream);
        runtime->configured = false;
        runtime->buffer_size = 0;
        runtime->buffer_bytes = 0;
        runtime->period_size = 0;
        runtime->period_bytes = 0;
        runtime->frame_bytes = 0;
        runtime->frame_bits = 0;
        runtime->sample_bits = 0;
        runtime->rate = 0;
        runtime->channels = 0;
        ret = 0;
        break;
    case SNDRV_PCM_IOCTL_SW_PARAMS: {
        snd_pcm_sw_params_t params;
        if (!args || copy_from_user(&params, args, sizeof(params))) {
            ret = -EFAULT;
            break;
        }
        if (!runtime->configured) {
            ret = -EBADFD;
            break;
        }
        runtime->avail_min =
            params.avail_min ? params.avail_min : runtime->period_size;
        runtime->start_threshold = params.start_threshold;
        runtime->stop_threshold = params.stop_threshold ? params.stop_threshold
                                                        : runtime->buffer_size;
        runtime->boundary =
            params.boundary ? params.boundary : runtime->buffer_size * 4;
        runtime->tstamp_mode = params.tstamp_mode;
        runtime->tstamp_type = params.tstamp_type;
        params.proto = SNDRV_PCM_VERSION;
        ret = copy_to_user(args, &params, sizeof(params)) ? -EFAULT : 0;
        sound_runtime_update_mmap(substream);
        break;
    }
    case SNDRV_PCM_IOCTL_STATUS:
    case SNDRV_PCM_IOCTL_STATUS_EXT: {
        snd_pcm_status_t status;
        sound_pcm_status_fill(substream, &status);
        ret =
            !args || copy_to_user(args, &status, sizeof(status)) ? -EFAULT : 0;
        break;
    }
    case SNDRV_PCM_IOCTL_DELAY: {
        snd_pcm_sframes_t delay = runtime->delay;
        ret = !args || copy_to_user(args, &delay, sizeof(delay)) ? -EFAULT : 0;
        break;
    }
    case SNDRV_PCM_IOCTL_HWSYNC:
        if (substream->ops && substream->ops->pump) {
            ret = sound_pcm_backend_validate(substream);
            if (ret < 0) {
                break;
            }
            substream->ops->pump(substream);
        }
        ret = 0;
        break;
    case SNDRV_PCM_IOCTL_SYNC_PTR: {
        snd_pcm_sync_ptr_t sync;
        if (!args || copy_from_user(&sync, args, sizeof(sync))) {
            ret = -EFAULT;
            break;
        }
        ret = sound_pcm_sync_ptr_apply(substream, &sync);
        if (ret == 0 && copy_to_user(args, &sync, sizeof(sync))) {
            ret = -EFAULT;
        }
        break;
    }
    case SNDRV_PCM_IOCTL_CHANNEL_INFO: {
        snd_pcm_channel_info_t info;
        if (!args || copy_from_user(&info, args, sizeof(info))) {
            ret = -EFAULT;
            break;
        }
        if (!runtime->configured || !runtime->frame_bits) {
            ret = -EBADFD;
            break;
        }
        if (info.channel >= runtime->channels) {
            ret = -EINVAL;
            break;
        }
        info.offset = SNDRV_PCM_MMAP_OFFSET_DATA;
        info.first = info.channel * runtime->sample_bits;
        info.step = runtime->frame_bits;
        ret = copy_to_user(args, &info, sizeof(info)) ? -EFAULT : 0;
        break;
    }
    case SNDRV_PCM_IOCTL_PREPARE:
        if (!runtime->configured) {
            ret = -EINVAL;
            break;
        }
        sound_runtime_reset(substream);
        runtime->configured = true;
        runtime->prepared = true;
        sound_runtime_set_state(substream, SNDRV_PCM_STATE_PREPARED);
        if (substream->ops && substream->ops->prepare) {
            ret = sound_pcm_backend_validate(substream);
            if (ret < 0) {
                break;
            }
            ret = substream->ops->prepare(substream);
        } else {
            ret = 0;
        }
        break;
    case SNDRV_PCM_IOCTL_RESET:
        if (!runtime->configured) {
            ret = -EBADFD;
            break;
        }
        sound_runtime_reset(substream);
        runtime->configured = true;
        ret = 0;
        break;
    case SNDRV_PCM_IOCTL_START:
        if (!runtime->configured) {
            ret = -EINVAL;
            break;
        }
        runtime->prepared = true;
        runtime->running = true;
        runtime->trigger_ns = nano_time();
        sound_runtime_set_state(substream, SNDRV_PCM_STATE_RUNNING);
        if (substream->ops && substream->ops->trigger) {
            ret = sound_pcm_backend_validate(substream);
            if (ret < 0) {
                break;
            }
            ret = substream->ops->trigger(substream, true);
        } else {
            ret = 0;
        }
        break;
    case SNDRV_PCM_IOCTL_DROP:
        runtime->running = false;
        runtime->draining = false;
        sound_runtime_set_state(substream, SNDRV_PCM_STATE_SETUP);
        if (substream->ops && substream->ops->trigger) {
            ret = sound_pcm_backend_validate(substream);
            if (ret < 0) {
                break;
            }
            ret = substream->ops->trigger(substream, false);
        } else {
            ret = 0;
        }
        break;
    case SNDRV_PCM_IOCTL_DRAIN:
        runtime->draining = true;
        runtime->running = true;
        sound_runtime_set_state(substream, SNDRV_PCM_STATE_DRAINING);
        if (substream->ops && substream->ops->drain) {
            ret = sound_pcm_backend_validate(substream);
            if (ret < 0) {
                break;
            }
            ret = substream->ops->drain(substream);
        } else {
            ret = 0;
        }
        break;
    case SNDRV_PCM_IOCTL_PAUSE: {
        int pause = 0;
        if (!args || copy_from_user(&pause, args, sizeof(pause))) {
            ret = -EFAULT;
            break;
        }
        runtime->running = pause == 0;
        sound_runtime_set_state(substream, pause ? SNDRV_PCM_STATE_PAUSED
                                                 : SNDRV_PCM_STATE_RUNNING);
        ret = 0;
        break;
    }
    case SNDRV_PCM_IOCTL_REWIND:
    case SNDRV_PCM_IOCTL_FORWARD:
        ret = 0;
        break;
    case SNDRV_PCM_IOCTL_RESUME:
        runtime->running = true;
        sound_runtime_set_state(substream, SNDRV_PCM_STATE_RUNNING);
        ret = 0;
        break;
    case SNDRV_PCM_IOCTL_XRUN:
        sound_runtime_set_state(substream, SNDRV_PCM_STATE_XRUN);
        ret = 0;
        break;
    case SNDRV_PCM_IOCTL_WRITEI_FRAMES: {
        snd_xferi_t xfer;
        if (!args || copy_from_user(&xfer, args, sizeof(xfer))) {
            ret = -EFAULT;
            break;
        }
        ret = sound_pcm_write_frames_locked(substream, &xfer);
        if (ret == 0 && copy_to_user(args, &xfer, sizeof(xfer))) {
            ret = -EFAULT;
        }
        break;
    }
    default:
        ret = -ENOTTY;
        break;
    }

    mutex_unlock(&substream->lock);
    return ret;
}

static ssize_t sound_pcm_write(void *dev, void *buf, uint64_t offset,
                               size_t size, fd_t *fd) {
    sound_pcm_substream_t *substream = sound_dev_to_substream(dev);
    snd_xferi_t xfer;
    (void)offset;
    (void)fd;

    mutex_lock(&substream->lock);
    if (!substream->runtime.configured || !substream->runtime.frame_bytes) {
        mutex_unlock(&substream->lock);
        return -EBADFD;
    }
    memset(&xfer, 0, sizeof(xfer));
    xfer.buf = buf;
    xfer.frames = sound_bytes_to_frames(&substream->runtime, size);
    ssize_t ret = sound_pcm_write_frames_locked(substream, &xfer);
    mutex_unlock(&substream->lock);
    return ret < 0 ? ret
                   : sound_frames_to_bytes(&substream->runtime, xfer.result);
}

static ssize_t sound_pcm_poll(void *dev, int events) {
    sound_pcm_substream_t *substream = sound_dev_to_substream(dev);
    sound_pcm_runtime_t *runtime = &substream->runtime;
    ssize_t ready = EPOLLERR;

    mutex_lock(&substream->lock);
    if (substream->ops && substream->ops->pump) {
        int ret = sound_pcm_backend_validate(substream);
        if (ret < 0) {
            mutex_unlock(&substream->lock);
            return EPOLLERR;
        }
        substream->ops->pump(substream);
    }

    ready = 0;
    if (runtime->state == SNDRV_PCM_STATE_XRUN) {
        ready |= EPOLLERR;
    }
    if ((events & EPOLLOUT) &&
        sound_runtime_avail(runtime) >= runtime->avail_min) {
        ready |= EPOLLOUT;
    }
    if ((events & EPOLLIN) && substream->stream == SNDRV_PCM_STREAM_CAPTURE) {
        ready |= EPOLLIN;
    }
    mutex_unlock(&substream->lock);
    return ready;
}

static void *sound_pcm_map(void *dev, void *addr, size_t offset, size_t size,
                           size_t prot, fd_t *fd) {
    sound_pcm_substream_t *substream = sound_dev_to_substream(dev);
    sound_pcm_runtime_t *runtime = &substream->runtime;
    uint64_t paddr = 0;
    uint64_t pt_flags = PT_FLAG_U;
    (void)fd;

    mutex_lock(&substream->lock);
    if (!runtime->configured && offset == SNDRV_PCM_MMAP_OFFSET_DATA) {
        mutex_unlock(&substream->lock);
        return (void *)(int64_t)-EBADFD;
    }

    if (offset == SNDRV_PCM_MMAP_OFFSET_STATUS) {
        if (!runtime->mmap_status &&
            sound_runtime_allocate_control_pages(substream) < 0) {
            mutex_unlock(&substream->lock);
            return (void *)(int64_t)-ENOMEM;
        }
        if (!runtime->mmap_status) {
            mutex_unlock(&substream->lock);
            return (void *)(int64_t)-EBADFD;
        }
        paddr = virt_to_phys(runtime->mmap_status);
    } else if (offset == SNDRV_PCM_MMAP_OFFSET_CONTROL) {
        if (!runtime->mmap_control &&
            sound_runtime_allocate_control_pages(substream) < 0) {
            mutex_unlock(&substream->lock);
            return (void *)(int64_t)-ENOMEM;
        }
        if (!runtime->mmap_control) {
            mutex_unlock(&substream->lock);
            return (void *)(int64_t)-EBADFD;
        }
        paddr = virt_to_phys(runtime->mmap_control);
    } else if (offset < runtime->buffer_bytes) {
        if (!runtime->configured || !runtime->dma_area) {
            mutex_unlock(&substream->lock);
            return (void *)(int64_t)-EBADFD;
        }
        paddr = virt_to_phys(runtime->dma_area + offset);
    } else {
        mutex_unlock(&substream->lock);
        return (void *)(int64_t)-EINVAL;
    }

    if (prot & PROT_READ) {
        pt_flags |= PT_FLAG_R;
    }
    if (prot & PROT_WRITE) {
        pt_flags |= PT_FLAG_W;
    }
    if (prot & PROT_EXEC) {
        pt_flags |= PT_FLAG_X;
    }
    if (!(pt_flags & (PT_FLAG_R | PT_FLAG_W | PT_FLAG_X))) {
        pt_flags |= PT_FLAG_R;
    }

    map_page_range(task_mm_pgdir(current_task->mm), (uint64_t)addr, paddr, size,
                   pt_flags);
    mutex_unlock(&substream->lock);
    return addr;
}

static ssize_t sound_ctl_ioctl(void *dev, int cmd, void *args, fd_t *fd) {
    sound_card_t *card = sound_dev_to_card(dev);
    ssize_t ret = -ENOTTY;
    (void)fd;

    mutex_lock(&card->lock);
    switch ((uint32_t)cmd) {
    case SNDRV_CTL_IOCTL_PVERSION:
        ret =
            !args || copy_to_user(args, &(int){SNDRV_CTL_VERSION}, sizeof(int))
                ? -EFAULT
                : 0;
        break;
    case SNDRV_CTL_IOCTL_CARD_INFO: {
        snd_ctl_card_info_t info;
        memset(&info, 0, sizeof(info));
        info.card = (int)card->index;
        strncpy((char *)info.id, card->id, sizeof(info.id) - 1);
        strncpy((char *)info.driver, card->driver, sizeof(info.driver) - 1);
        strncpy((char *)info.name, card->name, sizeof(info.name) - 1);
        strncpy((char *)info.longname, card->longname,
                sizeof(info.longname) - 1);
        strncpy((char *)info.mixername, card->mixername,
                sizeof(info.mixername) - 1);
        strncpy((char *)info.components, card->components,
                sizeof(info.components) - 1);
        ret = !args || copy_to_user(args, &info, sizeof(info)) ? -EFAULT : 0;
        break;
    }
    case SNDRV_CTL_IOCTL_PCM_NEXT_DEVICE: {
        int next = -1;
        int current = -1;
        if (!args || copy_from_user(&current, args, sizeof(current))) {
            ret = -EFAULT;
            break;
        }
        for (uint32_t i = (current < 0) ? 0U : (uint32_t)(current + 1);
             i < SOUND_MAX_PCM_DEVICES; i++) {
            if (sound_pcm_devices[card->index][i]) {
                next = (int)i;
                break;
            }
        }
        ret = copy_to_user(args, &next, sizeof(next)) ? -EFAULT : 0;
        break;
    }
    case SNDRV_CTL_IOCTL_PCM_INFO: {
        snd_pcm_info_t info;
        sound_pcm_substream_t *substream = NULL;
        if (!args || copy_from_user(&info, args, sizeof(info))) {
            ret = -EFAULT;
            break;
        }
        sound_pcm_device_t *pcm = sound_find_pcm_device(card, info.device);
        if (!pcm || info.stream < 0 ||
            info.stream >= SOUND_MAX_PCM_SUBSTREAMS ||
            !(substream = pcm->streams[info.stream])) {
            ret = -ENOENT;
            break;
        }
        sound_fill_pcm_info(substream, &info);
        ret = copy_to_user(args, &info, sizeof(info)) ? -EFAULT : 0;
        break;
    }
    case SNDRV_CTL_IOCTL_PCM_PREFER_SUBDEVICE: {
        int subdevice = 0;
        if (!args || copy_from_user(&subdevice, args, sizeof(subdevice))) {
            ret = -EFAULT;
            break;
        }
        card->preferred_subdevice = subdevice;
        ret = 0;
        break;
    }
    case SNDRV_CTL_IOCTL_ELEM_LIST: {
        snd_ctl_elem_list_t list;
        if (!args || copy_from_user(&list, args, sizeof(list))) {
            ret = -EFAULT;
            break;
        }
        list.count = 0;
        list.used = 0;
        ret = copy_to_user(args, &list, sizeof(list)) ? -EFAULT : 0;
        break;
    }
    case SNDRV_CTL_IOCTL_ELEM_INFO:
    case SNDRV_CTL_IOCTL_ELEM_READ:
    case SNDRV_CTL_IOCTL_ELEM_WRITE:
        ret = -ENOENT;
        break;
    case SNDRV_CTL_IOCTL_SUBSCRIBE_EVENTS: {
        int enabled = 0;
        if (!args || copy_from_user(&enabled, args, sizeof(enabled))) {
            ret = -EFAULT;
            break;
        }
        ret = copy_to_user(args, &enabled, sizeof(enabled)) ? -EFAULT : 0;
        break;
    }
    case SNDRV_CTL_IOCTL_POWER:
    case SNDRV_CTL_IOCTL_POWER_STATE:
        ret = !args || copy_to_user(args, &card->power_state, sizeof(int))
                  ? -EFAULT
                  : 0;
        break;
    default:
        ret = -ENOTTY;
        break;
    }
    mutex_unlock(&card->lock);
    return ret;
}

static sound_pcm_substream_t *sound_lookup_substream_by_path(const char *path) {
    for (uint32_t card_idx = 0; card_idx < SOUND_MAX_CARDS; card_idx++) {
        for (uint32_t dev_idx = 0; dev_idx < SOUND_MAX_PCM_DEVICES; dev_idx++) {
            sound_pcm_device_t *pcm = sound_pcm_devices[card_idx][dev_idx];
            if (!pcm) {
                continue;
            }
            for (uint32_t stream = 0; stream < SOUND_MAX_PCM_SUBSTREAMS;
                 stream++) {
                sound_pcm_substream_t *substream = pcm->streams[stream];
                if (substream && strcmp(substream->path, path) == 0) {
                    return substream;
                }
            }
        }
    }
    return NULL;
}

static void sound_register_node(const char *path) {
    struct vfs_file *file = NULL;
    struct vfs_open_how how = {0};
    int ret = vfs_openat(AT_FDCWD, path, &how, &file);
    if (ret < 0 || !file || !file->f_inode) {
        return;
    }

    if (!strncmp(path, "/dev/snd/pcm", 12)) {
        sound_pcm_substream_t *substream =
            sound_lookup_substream_by_path(path + strlen("/dev/"));
        if (substream) {
            substream->node = vfs_igrab(file->f_inode);
            substream->node_registered = true;
            vfs_file_put(file);
            return;
        }
    }

    vfs_file_put(file);
}

int sound_init(void) {
    if (sound_ready) {
        return 0;
    }

    vfs_mkdirat(AT_FDCWD, "/dev/snd", 0600);
    sound_ready = true;
    return 0;
}

sound_card_t *sound_card_create(const char *driver, const char *id,
                                const char *name, const char *longname,
                                const char *mixername, const char *components) {
    sound_card_t *card = NULL;
    char path[32];
    char dev_name[24];

    if (sound_init() != 0) {
        return NULL;
    }

    spin_lock(&sound_registry_lock);
    if (sound_cards_count >= SOUND_MAX_CARDS) {
        spin_unlock(&sound_registry_lock);
        return NULL;
    }
    card = calloc(1, sizeof(*card));
    if (!card) {
        spin_unlock(&sound_registry_lock);
        return NULL;
    }
    card->index = sound_cards_count++;
    sound_cards[card->index] = card;
    spin_unlock(&sound_registry_lock);

    mutex_init(&card->lock);
    strncpy(card->driver, driver ? driver : "sound", sizeof(card->driver) - 1);
    strncpy(card->id, id ? id : "soundcard", sizeof(card->id) - 1);
    strncpy(card->name, name ? name : "Sound Card", sizeof(card->name) - 1);
    strncpy(card->longname, longname ? longname : card->name,
            sizeof(card->longname) - 1);
    strncpy(card->mixername, mixername ? mixername : card->driver,
            sizeof(card->mixername) - 1);
    strncpy(card->components, components ? components : card->driver,
            sizeof(card->components) - 1);
    card->power_state = SNDRV_CTL_POWER_D0;

    snprintf(dev_name, sizeof(dev_name), "snd/controlC%u", card->index);
    card->control_dev = device_install_with_minor(
        DEV_CHAR, DEV_SOUND, card, dev_name, 0, NULL, NULL, sound_ctl_ioctl,
        NULL, NULL, NULL, NULL, card->index);

    snprintf(path, sizeof(path), "/dev/%s", dev_name);
    sound_register_node(path);
    return card;
}

sound_pcm_device_t *sound_find_pcm_device(sound_card_t *card, uint32_t device) {
    if (!card || device >= SOUND_MAX_PCM_DEVICES) {
        return NULL;
    }
    return sound_pcm_devices[card->index][device];
}

sound_pcm_substream_t *sound_pcm_create(const sound_pcm_create_info_t *info) {
    sound_pcm_device_t *pcm = NULL;
    sound_pcm_substream_t *substream = NULL;
    char dev_name[32];
    char path[48];

    if (!info || !info->card || info->device_id >= SOUND_MAX_PCM_DEVICES ||
        info->stream >= SOUND_MAX_PCM_SUBSTREAMS) {
        return NULL;
    }

    if (sound_init() != 0) {
        return NULL;
    }

    pcm = sound_pcm_devices[info->card->index][info->device_id];
    if (!pcm) {
        pcm = calloc(1, sizeof(*pcm));
        if (!pcm) {
            return NULL;
        }
        pcm->card = info->card;
        pcm->device_id = info->device_id;
        strncpy(pcm->id, info->id ? info->id : "pcm", sizeof(pcm->id) - 1);
        strncpy(pcm->name, info->name ? info->name : "PCM Device",
                sizeof(pcm->name) - 1);
        strncpy(pcm->subname, info->subname ? info->subname : "Subdevice #0",
                sizeof(pcm->subname) - 1);
        sound_pcm_devices[info->card->index][info->device_id] = pcm;
    }

    substream = calloc(1, sizeof(*substream));
    if (!substream) {
        return NULL;
    }
    substream->pcm = pcm;
    substream->device_id = info->device_id;
    substream->stream = info->stream;
    substream->subdevice = info->subdevice;
    substream->ops = info->ops;
    substream->driver_data = info->driver_data;
    substream->caps = *info->caps;
    mutex_init(&substream->lock);

    strncpy(substream->id, info->id ? info->id : pcm->id,
            sizeof(substream->id) - 1);
    strncpy(substream->name, info->name ? info->name : pcm->name,
            sizeof(substream->name) - 1);
    strncpy(substream->subname, info->subname ? info->subname : pcm->subname,
            sizeof(substream->subname) - 1);

    snprintf(dev_name, sizeof(dev_name), "snd/pcmC%uD%u%c", info->card->index,
             info->device_id,
             info->stream == SNDRV_PCM_STREAM_PLAYBACK ? 'p' : 'c');
    strncpy(substream->path, dev_name, sizeof(substream->path) - 1);
    substream->dev = device_install_with_minor(
        DEV_CHAR, DEV_SOUND, substream, substream->path, 0, sound_pcm_open,
        sound_pcm_close, sound_pcm_ioctl, sound_pcm_poll, NULL, sound_pcm_write,
        sound_pcm_map, info->minor);

    snprintf(path, sizeof(path), "/dev/%s", substream->path);
    sound_register_node(path);

    pcm->streams[info->stream] = substream;
    sound_runtime_reset(substream);
    return substream;
}

void sound_pcm_notify(sound_pcm_substream_t *substream) {
    if (!substream || !substream->node_registered || !substream->node) {
        return;
    }

    vfs_poll_notify(substream->node, EPOLLOUT | EPOLLIN);
}

int dlmain(void) { return sound_init(); }
