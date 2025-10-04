// usb_hid.c
#include "hid.h"

// 全局 HID 设备列表
static usb_hid_device_t *hid_devices = NULL;
static int hid_device_count = 0;

// 获取 HID 描述符
static int hid_get_descriptor(usb_hid_device_t *hid, uint8_t type, void *buffer,
                              uint16_t length) {
    usb_device_request_t setup = {
        .bmRequestType = USB_DIR_IN | USB_TYPE_STANDARD | USB_RECIP_INTERFACE,
        .bRequest = USB_REQ_GET_DESCRIPTOR,
        .wValue = (type << 8) | 0,
        .wIndex = hid->interface_number,
        .wLength = length};

    return usb_control_transfer(hid->usb_device, &setup, buffer, length, NULL,
                                NULL);
}

// 设置协议
int hid_set_protocol(usb_hid_device_t *hid, uint8_t protocol) {
    printk("HID: Setting protocol to %s\n",
           protocol == HID_PROTOCOL_BOOT ? "Boot" : "Report");

    usb_device_request_t setup = {
        .bmRequestType = USB_DIR_OUT | USB_TYPE_CLASS | USB_RECIP_INTERFACE,
        .bRequest = HID_REQ_SET_PROTOCOL,
        .wValue = protocol,
        .wIndex = hid->interface_number,
        .wLength = 0};

    return usb_control_transfer(hid->usb_device, &setup, NULL, 0, NULL, NULL);
}

// 设置空闲
int hid_set_idle(usb_hid_device_t *hid, uint8_t duration) {
    printk("HID: Setting idle duration to %d ms\n", duration * 4);

    usb_device_request_t setup = {
        .bmRequestType = USB_DIR_OUT | USB_TYPE_CLASS | USB_RECIP_INTERFACE,
        .bRequest = HID_REQ_SET_IDLE,
        .wValue =
            (duration << 8) | 0, // Duration in high byte, Report ID in low
        .wIndex = hid->interface_number,
        .wLength = 0};

    return usb_control_transfer(hid->usb_device, &setup, NULL, 0, NULL, NULL);
}

// 中断传输回调
static void hid_interrupt_callback(usb_transfer_t *transfer) {
    usb_hid_device_t *hid = (usb_hid_device_t *)transfer->user_data;

    if (transfer->status != 0) {
        printk("HID: Interrupt transfer failed: %d\n", transfer->status);
        hid->transfer_active = false;
        return;
    }

    if (transfer->actual_length == 0) {
        printk("HID: Empty interrupt transfer\n");
        goto resubmit;
    }

    // 根据设备类型处理数据
    if (hid->device_type == HID_TYPE_KEYBOARD) {
        hid_keyboard_report_t *report =
            (hid_keyboard_report_t *)transfer->buffer;

        // 保存当前报告
        memcpy(&hid->prev_keyboard_report, &hid->keyboard_report,
               sizeof(hid_keyboard_report_t));
        memcpy(&hid->keyboard_report, report, sizeof(hid_keyboard_report_t));

        // 检测按键变化并生成事件
        if (hid->event_callback) {
            // 检测新按下的键
            for (int i = 0; i < 6; i++) {
                uint8_t key = report->keys[i];
                if (key == 0)
                    continue;

                // 检查是否是新按键
                bool is_new = true;
                for (int j = 0; j < 6; j++) {
                    if (hid->prev_keyboard_report.keys[j] == key) {
                        is_new = false;
                        break;
                    }
                }

                if (is_new) {
                    hid_event_t event = {.type = HID_EVENT_KEY_PRESS,
                                         .key = {.keycode = key,
                                                 .modifiers = report->modifiers,
                                                 .pressed = true}};

                    hid->event_callback(&event, hid->callback_user_data);
                }
            }

            // 检测释放的键
            for (int i = 0; i < 6; i++) {
                uint8_t key = hid->prev_keyboard_report.keys[i];
                if (key == 0)
                    continue;

                // 检查键是否仍然按下
                bool still_pressed = false;
                for (int j = 0; j < 6; j++) {
                    if (report->keys[j] == key) {
                        still_pressed = true;
                        break;
                    }
                }

                if (!still_pressed) {
                    hid_event_t event = {.type = HID_EVENT_KEY_RELEASE,
                                         .key = {.keycode = key,
                                                 .modifiers = report->modifiers,
                                                 .pressed = false}};

                    hid->event_callback(&event, hid->callback_user_data);
                }
            }
        }

    } else if (hid->device_type == HID_TYPE_MOUSE) {
        hid_mouse_report_t *report = (hid_mouse_report_t *)transfer->buffer;

        printk("  Mouse: buttons=0x%02x, x=%d, y=%d", report->buttons,
               report->x, report->y);

        if (transfer->actual_length >= 4) {
            printk(", wheel=%d", report->wheel);
        }
        printk("\n");

        // 保存报告
        memcpy(&hid->prev_mouse_report, &hid->mouse_report,
               sizeof(hid_mouse_report_t));
        memcpy(&hid->mouse_report, report,
               transfer->actual_length < sizeof(hid_mouse_report_t)
                   ? transfer->actual_length
                   : sizeof(hid_mouse_report_t));

        // 生成鼠标事件
        if (hid->event_callback) {
            // 移动事件
            if (report->x != 0 || report->y != 0 || report->wheel != 0) {
                hid_event_t event = {.type = HID_EVENT_MOUSE_MOVE,
                                     .mouse = {.x = report->x,
                                               .y = report->y,
                                               .wheel = report->wheel,
                                               .buttons = report->buttons}};

                hid->event_callback(&event, hid->callback_user_data);
            }

            // 按键事件
            if (report->buttons != hid->prev_mouse_report.buttons) {
                hid_event_t event = {.type = HID_EVENT_MOUSE_BUTTON,
                                     .mouse = {.x = 0,
                                               .y = 0,
                                               .wheel = 0,
                                               .buttons = report->buttons}};

                hid->event_callback(&event, hid->callback_user_data);
            }
        }
    }

resubmit:
    // 重新提交传输以继续接收
    if (hid->transfer_active) {
        usb_interrupt_transfer(hid->usb_device, hid->interrupt_in_ep,
                               hid->input_buffer, hid->input_buffer_size,
                               hid_interrupt_callback, hid);
    }
}

// 启动中断传输
static int hid_start_interrupt_transfer(usb_hid_device_t *hid) {
    printk("HID: Starting interrupt transfers\n");

    hid->transfer_active = true;

    int ret = usb_interrupt_transfer(hid->usb_device, hid->interrupt_in_ep,
                                     hid->input_buffer, hid->input_buffer_size,
                                     hid_interrupt_callback, hid);

    if (ret < 0) {
        printk("HID: Failed to start interrupt transfer\n");
        hid->transfer_active = false;
        return ret;
    }

    printk("HID: Interrupt transfers started\n");
    return 0;
}

// 探测 HID 设备
int usb_hid_probe(usb_device_t *device) {
    if (!device) {
        return -1;
    }

    printk("\n========== USB HID Device Probe ==========\n");

    // 检查设备类
    bool is_hid = false;

    if (device->descriptor.bDeviceClass == USB_CLASS_HID) {
        is_hid = true;
        printk("HID: Device-level HID class\n");
    }

    // 解析配置描述符查找 HID 接口
    if (!device->config_descriptor) {
        printk("HID: No configuration descriptor\n");
        return -1;
    }

    uint8_t *ptr = (uint8_t *)device->config_descriptor;
    uint8_t *end = ptr + device->config_descriptor->wTotalLength;
    ptr += sizeof(usb_config_descriptor_t);

    usb_interface_descriptor_t *hid_iface = NULL;
    hid_descriptor_t *hid_desc_ptr = NULL;
    usb_endpoint_descriptor_t *interrupt_in = NULL;

    while (ptr < end) {
        uint8_t len = ptr[0];
        uint8_t type = ptr[1];

        if (len == 0)
            break;
        if (ptr + len > end)
            break;

        if (type == USB_DT_INTERFACE) {
            usb_interface_descriptor_t *iface =
                (usb_interface_descriptor_t *)ptr;

            if (iface->bInterfaceClass == USB_CLASS_HID) {
                hid_iface = iface;
                is_hid = true;

                printk("HID: Found HID interface %d\n",
                       iface->bInterfaceNumber);
                printk("  Subclass: 0x%02x (%s)\n", iface->bInterfaceSubClass,
                       iface->bInterfaceSubClass == HID_SUBCLASS_BOOT ? "Boot"
                                                                      : "None");
                printk("  Protocol: 0x%02x (%s)\n", iface->bInterfaceProtocol,
                       iface->bInterfaceProtocol == HID_PROTOCOL_KEYBOARD
                           ? "Keyboard"
                       : iface->bInterfaceProtocol == HID_PROTOCOL_MOUSE
                           ? "Mouse"
                           : "None");
            }
        } else if (type == HID_DT_HID && hid_iface) {
            hid_desc_ptr = (hid_descriptor_t *)ptr;

            printk("HID Descriptor:\n");
            printk("  bcdHID: 0x%04x\n", hid_desc_ptr->bcdHID);
            printk("  Country: %d\n", hid_desc_ptr->bCountryCode);
            printk("  Descriptors: %d\n", hid_desc_ptr->bNumDescriptors);
            printk("  Report Desc Type: 0x%02x\n",
                   hid_desc_ptr->bDescriptorType2);
            printk("  Report Desc Length: %d\n",
                   hid_desc_ptr->wDescriptorLength);

        } else if (type == USB_DT_ENDPOINT && hid_iface) {
            usb_endpoint_descriptor_t *ep = (usb_endpoint_descriptor_t *)ptr;

            if ((ep->bmAttributes & 0x03) == USB_ENDPOINT_XFER_INT) {
                if (ep->bEndpointAddress & 0x80) {
                    interrupt_in = ep;
                    printk(
                        "  Interrupt IN: 0x%02x, MaxPacket=%d, Interval=%d\n",
                        ep->bEndpointAddress, ep->wMaxPacketSize,
                        ep->bInterval);
                }
            }
        }

        ptr += len;
    }

    if (!is_hid || !hid_iface || !interrupt_in) {
        printk("HID: Required descriptors not found\n");
        return -1;
    }

    // 创建 HID 设备结构
    usb_hid_device_t *hid =
        (usb_hid_device_t *)malloc(sizeof(usb_hid_device_t));
    if (!hid) {
        printk("HID: Failed to allocate device structure\n");
        return -1;
    }

    memset(hid, 0, sizeof(usb_hid_device_t));
    hid->usb_device = device;
    hid->interface_number = hid_iface->bInterfaceNumber;
    hid->interrupt_in_ep = interrupt_in->bEndpointAddress;
    hid->interrupt_in_max_packet = interrupt_in->wMaxPacketSize;
    hid->interrupt_interval = interrupt_in->bInterval;

    if (hid_desc_ptr) {
        memcpy(&hid->hid_desc, hid_desc_ptr, sizeof(hid_descriptor_t));
    }

    // 确定设备类型
    if (hid_iface->bInterfaceProtocol == HID_PROTOCOL_KEYBOARD) {
        hid->device_type = HID_TYPE_KEYBOARD;
        hid->protocol = HID_PROTOCOL_KEYBOARD;
        printk("HID: Device type: KEYBOARD\n");
    } else if (hid_iface->bInterfaceProtocol == HID_PROTOCOL_MOUSE) {
        hid->device_type = HID_TYPE_MOUSE;
        hid->protocol = HID_PROTOCOL_MOUSE;
        printk("HID: Device type: MOUSE\n");
    } else {
        hid->device_type = HID_TYPE_GENERIC;
        printk("HID: Device type: GENERIC\n");
    }

    // 分配输入缓冲区
    hid->input_buffer_size = hid->interrupt_in_max_packet;
    hid->input_buffer = (uint8_t *)malloc(hid->input_buffer_size);
    if (!hid->input_buffer) {
        printk("HID: Failed to allocate input buffer\n");
        free(hid);
        return -1;
    }

    // 设置 Boot Protocol（如果支持）
    if (hid_iface->bInterfaceSubClass == HID_SUBCLASS_BOOT) {
        printk("HID: Setting Boot Protocol\n");
        hid_set_protocol(hid, HID_PROTOCOL_BOOT);
    }

    // 设置空闲时间（0 = 无限期）
    hid_set_idle(hid, 0);

    // 启动中断传输
    if (hid_start_interrupt_transfer(hid) != 0) {
        printk("HID: Failed to start interrupt transfers\n");
        free(hid->input_buffer);
        free(hid);
        return -1;
    }

    // 添加到设备列表
    hid->next = hid_devices;
    hid_devices = hid;
    hid_device_count++;

    printk("\n========== HID Device Ready ==========\n");
    printk("Type: %s\n", hid->device_type == HID_TYPE_KEYBOARD ? "Keyboard"
                         : hid->device_type == HID_TYPE_MOUSE  ? "Mouse"
                                                               : "Generic");
    printk("Interrupt EP: 0x%02x\n", hid->interrupt_in_ep);
    printk("Max Packet: %d\n", hid->interrupt_in_max_packet);
    printk("=====================================\n\n");

    return 0;
}

// 移除 HID 设备
void usb_hid_remove(usb_hid_device_t *hid) {
    if (!hid)
        return;

    printk("HID: Removing device\n");

    // 停止传输
    hid->transfer_active = false;

    // 从列表移除
    usb_hid_device_t **prev = &hid_devices;
    while (*prev) {
        if (*prev == hid) {
            *prev = hid->next;
            hid_device_count--;
            break;
        }
        prev = &(*prev)->next;
    }

    if (hid->input_buffer) {
        free(hid->input_buffer);
    }

    free(hid);
}

// 设置事件回调
void usb_hid_set_event_callback(usb_hid_device_t *hid,
                                hid_event_callback_t callback,
                                void *user_data) {
    if (!hid)
        return;

    hid->event_callback = callback;
    hid->callback_user_data = user_data;
}

// 获取 HID 设备
usb_hid_device_t *usb_hid_get_device(int index) {
    usb_hid_device_t *hid = hid_devices;
    int i = 0;

    while (hid && i < index) {
        hid = hid->next;
        i++;
    }

    return hid;
}

usb_hid_device_t *usb_hid_get_keyboard(void) {
    usb_hid_device_t *hid = hid_devices;

    while (hid) {
        if (hid->device_type == HID_TYPE_KEYBOARD) {
            return hid;
        }
        hid = hid->next;
    }

    return NULL;
}

usb_hid_device_t *usb_hid_get_mouse(void) {
    usb_hid_device_t *hid = hid_devices;

    while (hid) {
        if (hid->device_type == HID_TYPE_MOUSE) {
            return hid;
        }
        hid = hid->next;
    }

    return NULL;
}

int hid_probe(usb_device_t *usbdev) { return usb_hid_probe(usbdev); }

int hid_remove(usb_device_t *usbdev) {
    usb_hid_remove((usb_hid_device_t *)usbdev->private_data);
    return 0;
}

usb_driver_t hid_driver = {
    .class = USB_CLASS_HID,
    .subclass = 0x00,
    .probe = hid_probe,
    .remove = hid_remove,
};

__attribute__((visibility("default"))) int dlmain() {
    register_usb_driver(&hid_driver);

    return 0;
}
