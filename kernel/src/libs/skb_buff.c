#include <libs/skb_buff.h>
#include <mm/mm.h>

void skb_queue_init(skb_queue_t *queue, size_t byte_limit,
                    skb_priv_destructor_t priv_destructor) {
    if (!queue)
        return;

    memset(queue, 0, sizeof(*queue));
    queue->byte_limit = byte_limit;
    queue->priv_destructor = priv_destructor;
}

void skb_queue_set_limit(skb_queue_t *queue, size_t byte_limit) {
    if (!queue)
        return;

    queue->byte_limit = byte_limit;
}

size_t skb_queue_bytes(const skb_queue_t *queue) {
    return queue ? queue->byte_count : 0;
}

size_t skb_queue_packets(const skb_queue_t *queue) {
    return queue ? queue->packet_count : 0;
}

size_t skb_queue_space(const skb_queue_t *queue) {
    if (!queue || queue->byte_count >= queue->byte_limit)
        return 0;

    return queue->byte_limit - queue->byte_count;
}

skb_buff_t *skb_alloc(size_t len) {
    skb_buff_t *skb = calloc(1, sizeof(*skb));
    if (!skb)
        return NULL;

    if (len > 0) {
        skb->data = malloc(len);
        if (!skb->data) {
            free(skb);
            return NULL;
        }
    }

    skb->len = len;
    return skb;
}

void skb_free(skb_buff_t *skb, skb_priv_destructor_t priv_destructor) {
    if (!skb)
        return;

    if (priv_destructor && skb->priv)
        priv_destructor(skb->priv);

    free(skb->data);
    free(skb);
}

size_t skb_unread_len(const skb_buff_t *skb) {
    if (!skb || skb->offset >= skb->len)
        return 0;

    return skb->len - skb->offset;
}

size_t skb_copy_data(const skb_buff_t *skb, size_t start, void *out,
                     size_t len) {
    size_t available = 0;

    if (!skb || !out || !len)
        return 0;

    available = skb_unread_len(skb);
    if (start >= available)
        return 0;

    size_t to_copy = MIN(len, available - start);
    memcpy(out, skb->data + skb->offset + start, to_copy);
    return to_copy;
}

void *skb_detach_priv(skb_buff_t *skb) {
    void *priv = NULL;

    if (!skb)
        return NULL;

    priv = skb->priv;
    skb->priv = NULL;
    return priv;
}

bool skb_queue_push(skb_queue_t *queue, skb_buff_t *skb) {
    size_t unread = 0;

    if (!queue || !skb)
        return false;

    unread = skb_unread_len(skb);
    if (unread > skb_queue_space(queue))
        return false;

    skb->next = NULL;
    if (queue->tail) {
        queue->tail->next = skb;
    } else {
        queue->head = skb;
    }
    queue->tail = skb;
    queue->packet_count++;
    queue->byte_count += unread;
    return true;
}

skb_buff_t *skb_queue_peek(const skb_queue_t *queue) {
    return queue ? queue->head : NULL;
}

skb_buff_t *skb_queue_pop(skb_queue_t *queue) {
    skb_buff_t *skb = NULL;

    if (!queue || !queue->head)
        return NULL;

    skb = queue->head;
    queue->head = skb->next;
    if (!queue->head)
        queue->tail = NULL;

    queue->packet_count--;
    queue->byte_count -= skb_unread_len(skb);
    skb->next = NULL;
    return skb;
}

void skb_queue_drop_head(skb_queue_t *queue) {
    skb_buff_t *skb = skb_queue_pop(queue);
    if (!skb)
        return;

    skb_free(skb, queue->priv_destructor);
}

void skb_queue_purge(skb_queue_t *queue) {
    if (!queue)
        return;

    while (queue->head)
        skb_queue_drop_head(queue);
}
