#include <drivers/bus/bus.h>
#include <fs/vfs/vfs.h>
#include <init/callbacks.h>

DEFINE_LLIST(devices);

attribute_t *attribute_new(const char *name, const char *value) {
    attribute_t *attr = malloc(sizeof(attribute_t));
    attr->name = strdup(name);
    attr->value = strdup(value);
    return attr;
}

void attribute_free(attribute_t *attr) {
    if (attr->name)
        free(attr->name);
    if (attr->value)
        free(attr->value);
    free(attr);
}

attributes_builder_t *attributes_builder_new() {
    attributes_builder_t *builder = calloc(1, sizeof(attributes_builder_t));
    builder->capability = 128;
    builder->attrs = calloc(builder->capability, sizeof(attribute_t *));
    return builder;
}

int attributes_builder_append(attributes_builder_t *builder,
                              attribute_t *attr) {
    if (builder->count >= builder->capability) {
        builder->capability *= 2;
        builder->attrs = realloc(builder->attrs, builder->capability);
    }
    builder->attrs[builder->count++] = attr;
    return 0;
}

bin_attributes_builder_t *bin_attributes_builder_new() {
    bin_attributes_builder_t *builder =
        calloc(1, sizeof(bin_attributes_builder_t));
    builder->capability = 128;
    builder->bin_attrs = calloc(builder->capability, sizeof(bin_attribute_t *));
    return builder;
}

int bin_attributes_builder_append(bin_attributes_builder_t *builder,
                                  bin_attribute_t *bin_attr) {
    if (builder->count >= builder->capability) {
        builder->capability *= 2;
        builder->bin_attrs = realloc(builder->bin_attrs, builder->capability);
    }
    builder->bin_attrs[builder->count++] = bin_attr;
    return 0;
}

bus_device_t *bus_device_install_internal(
    bus_t *bus, void *dev_data, attribute_t **extra_attrs,
    int extra_attrs_count, bin_attribute_t **extra_bin_attrs,
    int extra_bin_attrs_count,
    int (*get_device_path)(struct bus_device *device, char *buf,
                           size_t max_count)) {
    attributes_builder_t *builder = attributes_builder_new();
    for (int i = 0; i < bus->bus_default_attrs_count; i++) {
        attributes_builder_append(builder, bus->bus_default_attrs[i]);
    }
    for (int i = 0; i < extra_attrs_count; i++) {
        attributes_builder_append(builder, extra_attrs[i]);
    }

    bin_attributes_builder_t *bin_builder = bin_attributes_builder_new();
    for (int i = 0; i < bus->bus_default_bin_attrs_count; i++) {
        bin_attributes_builder_append(bin_builder,
                                      bus->bus_default_bin_attrs[i]);
    }
    for (int i = 0; i < extra_bin_attrs_count; i++) {
        bin_attributes_builder_append(bin_builder, extra_bin_attrs[i]);
    }

    bus_device_t *device = malloc(sizeof(bus_device_t));

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
}
