#include <drivers/bus/bus.h>
#include <fs/vfs/vfs.h>
#include <init/callbacks.h>

DEFINE_LLIST(devices);

attribute_t *attribute_new(const char *name, const char *value) {
    if (!name || !value)
        return NULL;

    attribute_t *attr = malloc(sizeof(attribute_t));
    if (!attr)
        return NULL;

    attr->name = strdup(name);
    attr->value = strdup(value);
    if (!attr->name || !attr->value) {
        attribute_free(attr);
        return NULL;
    }

    return attr;
}

void attribute_free(attribute_t *attr) {
    if (!attr)
        return;
    if (attr->name)
        free(attr->name);
    if (attr->value)
        free(attr->value);
    free(attr);
}

attributes_builder_t *attributes_builder_new() {
    attributes_builder_t *builder = calloc(1, sizeof(attributes_builder_t));
    if (!builder)
        return NULL;
    builder->capability = 128;
    builder->attrs = calloc(builder->capability, sizeof(attribute_t *));
    if (!builder->attrs) {
        free(builder);
        return NULL;
    }
    return builder;
}

int attributes_builder_append(attributes_builder_t *builder,
                              attribute_t *attr) {
    if (!builder || !builder->attrs || !attr)
        return -EINVAL;

    if (builder->count >= builder->capability) {
        int capability = builder->capability * 2;
        attribute_t **attrs =
            realloc(builder->attrs, capability * sizeof(*builder->attrs));
        if (!attrs)
            return -ENOMEM;
        builder->attrs = attrs;
        builder->capability = capability;
    }
    builder->attrs[builder->count++] = attr;
    return 0;
}

int attributes_builder_append_new(attributes_builder_t *builder,
                                  const char *name, const char *value) {
    attribute_t *attr = attribute_new(name, value);
    if (!attr)
        return -ENOMEM;

    int ret = attributes_builder_append(builder, attr);
    if (ret < 0)
        attribute_free(attr);
    return ret;
}

void attributes_builder_free(attributes_builder_t *builder) {
    if (!builder)
        return;
    free(builder->attrs);
    free(builder);
}

void attributes_builder_free_all(attributes_builder_t *builder) {
    if (!builder)
        return;
    for (int i = 0; i < builder->count; i++)
        attribute_free(builder->attrs[i]);
    attributes_builder_free(builder);
}

static void attributes_builder_free_range(attributes_builder_t *builder,
                                          int start) {
    if (!builder || start < 0)
        return;
    for (int i = start; i < builder->count; i++)
        attribute_free(builder->attrs[i]);
}

bin_attributes_builder_t *bin_attributes_builder_new() {
    bin_attributes_builder_t *builder =
        calloc(1, sizeof(bin_attributes_builder_t));
    if (!builder)
        return NULL;
    builder->capability = 128;
    builder->bin_attrs = calloc(builder->capability, sizeof(bin_attribute_t *));
    if (!builder->bin_attrs) {
        free(builder);
        return NULL;
    }
    return builder;
}

int bin_attributes_builder_append(bin_attributes_builder_t *builder,
                                  bin_attribute_t *bin_attr) {
    if (!builder || !builder->bin_attrs || !bin_attr)
        return -EINVAL;

    if (builder->count >= builder->capability) {
        int capability = builder->capability * 2;
        bin_attribute_t **bin_attrs = realloc(
            builder->bin_attrs, capability * sizeof(*builder->bin_attrs));
        if (!bin_attrs)
            return -ENOMEM;
        builder->bin_attrs = bin_attrs;
        builder->capability = capability;
    }
    builder->bin_attrs[builder->count++] = bin_attr;
    return 0;
}

static void bin_attributes_builder_free(bin_attributes_builder_t *builder) {
    if (!builder)
        return;
    free(builder->bin_attrs);
    free(builder);
}

bus_device_t *bus_device_install_internal(
    bus_t *bus, void *dev_data, attribute_t **extra_attrs,
    int extra_attrs_count, bin_attribute_t **extra_bin_attrs,
    int extra_bin_attrs_count,
    int (*get_device_path)(struct bus_device *device, char *buf,
                           size_t max_count)) {
    int owned_attrs_start = -1;
    if (!bus || !get_device_path || extra_attrs_count < 0 ||
        extra_bin_attrs_count < 0)
        return NULL;
    if ((extra_attrs_count > 0 && !extra_attrs) ||
        (extra_bin_attrs_count > 0 && !extra_bin_attrs))
        return NULL;

    attributes_builder_t *builder = attributes_builder_new();
    if (!builder || !builder->attrs)
        goto err_builder;
    for (int i = 0; i < bus->bus_default_attrs_count; i++) {
        if (attributes_builder_append(builder, bus->bus_default_attrs[i]) < 0)
            goto err_builder;
    }
    owned_attrs_start = builder->count;
    for (int i = 0; i < extra_attrs_count; i++) {
        attribute_t *attr = extra_attrs[i];
        if (!attr)
            goto err_builder;
        if (attributes_builder_append_new(builder, attr->name, attr->value) < 0)
            goto err_builder;
    }

    bin_attributes_builder_t *bin_builder = bin_attributes_builder_new();
    if (!bin_builder || !bin_builder->bin_attrs)
        goto err_bin_builder;
    for (int i = 0; i < bus->bus_default_bin_attrs_count; i++) {
        if (bin_attributes_builder_append(bin_builder,
                                          bus->bus_default_bin_attrs[i]) < 0)
            goto err_bin_builder;
    }
    for (int i = 0; i < extra_bin_attrs_count; i++) {
        if (bin_attributes_builder_append(bin_builder, extra_bin_attrs[i]) < 0)
            goto err_bin_builder;
    }

    bus_device_t *device = malloc(sizeof(bus_device_t));
    if (!device)
        goto err_bin_builder;

    llist_init_head(&device->node);

    device->bus = bus;
    device->private_data = dev_data;
    device->sysfs_path = NULL;
    device->bus_link_path = NULL;

    device->get_device_path = get_device_path;

    device->attrs = builder->attrs;
    device->attrs_count = builder->count;
    free(builder);
    device->bin_attrs = bin_builder->bin_attrs;
    device->bin_attrs_count = bin_builder->count;
    free(bin_builder);

    llist_append(&devices, &device->node);

    on_new_bus_device_call(device);

    return device;

err_bin_builder:
    bin_attributes_builder_free(bin_builder);
err_builder:
    attributes_builder_free_range(builder, owned_attrs_start);
    attributes_builder_free(builder);
    return NULL;
}
