#pragma once

#include <libs/klibc.h>

typedef void (*skb_priv_destructor_t)(void *priv);

typedef struct skb_buff {
    struct skb_buff *next;
    uint8_t *data;
    size_t len;
    size_t offset;
    uint32_t flags;
    void *priv;
} skb_buff_t;

typedef struct skb_queue {
    skb_buff_t *head;
    skb_buff_t *tail;
    size_t packet_count;
    size_t byte_count;
    size_t byte_limit;
    skb_priv_destructor_t priv_destructor;
} skb_queue_t;

void skb_queue_init(skb_queue_t *queue, size_t byte_limit,
                    skb_priv_destructor_t priv_destructor);
void skb_queue_purge(skb_queue_t *queue);
void skb_queue_set_limit(skb_queue_t *queue, size_t byte_limit);
size_t skb_queue_bytes(const skb_queue_t *queue);
size_t skb_queue_packets(const skb_queue_t *queue);
size_t skb_queue_space(const skb_queue_t *queue);

skb_buff_t *skb_alloc(size_t len);
void skb_free(skb_buff_t *skb, skb_priv_destructor_t priv_destructor);
size_t skb_unread_len(const skb_buff_t *skb);
size_t skb_copy_data(const skb_buff_t *skb, size_t start, void *out,
                     size_t len);
void *skb_detach_priv(skb_buff_t *skb);

bool skb_queue_push(skb_queue_t *queue, skb_buff_t *skb);
skb_buff_t *skb_queue_peek(const skb_queue_t *queue);
skb_buff_t *skb_queue_pop(skb_queue_t *queue);
void skb_queue_drop_head(skb_queue_t *queue);
