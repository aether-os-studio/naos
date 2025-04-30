#include <drivers/dtb/dtb.h>
#include <drivers/kernel_logger.h>

__attribute__((used, section(".limine_requests_start"))) static volatile struct limine_dtb_request dtb_request = {
    .id = LIMINE_DTB_REQUEST,
    .revision = 0,
};

// 解析DTB的主函数
void parse_dtb(const void *dtb)
{
    const struct fdt_header *header = dtb;

    // 1. 检查魔数
    if (header->magic != 0xd00dfeed)
    {
        printk("Invalid DTB magic: 0x%08x\n", header->magic);
        return;
    }

    // 2. 获取关键偏移量
    const char *struct_block = (const char *)dtb + header->off_dt_struct;
    const char *strings_block = (const char *)dtb + header->off_dt_strings;

    const char *p = struct_block;
    int depth = 0; // 当前节点深度

    // 3. 遍历结构块
    while (1)
    {
        uint32_t tag = *(const uint32_t *)p;
        p += 4;

        switch (tag)
        {
        // 节点开始（FDT_BEGIN_NODE）
        case 0x00000001:
        {
            const char *name = p;
            p += strlen(name) + 1;
            p = (const char *)(((uintptr_t)p + 3) & ~3); // 4字节对齐

            printk("%*sNode: %s\n", depth * 2, "", name);
            depth++;
            break;
        }

        // 节点结束（FDT_END_NODE）
        case 0x00000002:
            depth--;
            break;

        // 属性（FDT_PROP）
        case 0x00000003:
        {
            struct fdt_property *prop = (struct fdt_property *)p;
            const char *name = strings_block + prop->nameoff;
            const void *value = p + sizeof(struct fdt_property);
            p += sizeof(struct fdt_property) + ((prop->len + 3) & ~3);

            // 处理特定属性
            if (strcmp(name, "compatible") == 0)
            {
                printk("%*sCompatible: %s\n", depth * 2, "", (const char *)value);
            }
            else if (strcmp(name, "reg") == 0)
            {
                // 解析寄存器地址和长度（假设为64位地址）
                const uint64_t *reg = (const uint64_t *)value;
                printk("%*sReg: 0x%llx, Size: 0x%llx\n",
                       depth * 2, "",
                       (uint64_t)reg[0],
                       (uint64_t)reg[1]);
            }
            break;
        }

        // 结束标记（FDT_END）
        case 0x00000009:
            return;

        default:
            printk("Unknown tag: 0x%08x\n", tag);
            return;
        }
    }
}

void dtb_init()
{
    if (dtb_request.response != NULL && dtb_request.response->dtb_ptr != NULL)
    {
        parse_dtb((const void *)dtb_request.response->dtb_ptr);
    }
}
