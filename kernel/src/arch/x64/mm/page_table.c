#include <arch/x64/mm/page_table.h>
#include <mm/page_table_flags.h>

uint64_t get_arch_page_table_flags(uint64_t flags)
{
    uint64_t result = ARCH_PT_FLAG_VALID;

    if ((flags & PT_FLAG_W) != 0)
    {
        result |= ARCH_PT_FLAG_WRITEABLE;
    }

    if ((flags & PT_FLAG_U) != 0)
    {
        result |= ARCH_PT_FLAG_USER;
    }

    // if ((flags & PT_FLAG_X) == 0)
    // {
    //     result |= ARCH_PT_FLAG_NX;
    // }

    return result;
}

uint64_t *kernel_page_dir = NULL;

uint64_t *get_kernel_page_dir()
{
    return kernel_page_dir;
}

// 映射虚拟地址到物理地址
void map_page(uint64_t *pml4, uint64_t vaddr, uint64_t paddr, uint64_t flags)
{
    if (kernel_page_dir == NULL)
    {
        kernel_page_dir = pml4;
    }

    uint64_t indices[] = {
        (vaddr >> 39) & 0x1FF, // PML4索引
        (vaddr >> 30) & 0x1FF, // PDPT索引
        (vaddr >> 21) & 0x1FF, // PD索引
        (vaddr >> 12) & 0x1FF  // PT索引
    };

    uint64_t *current_table = pml4;

    // 遍历PML4, PDPT, PD
    for (int level = 0; level < 3; ++level)
    {
        uint64_t index = indices[level];
        uint64_t *entry = &current_table[index];

        if (!(*entry & ARCH_PT_FLAG_VALID))
        {
            uint64_t new_phys = alloc_frames(1);
            uint64_t *new_table = phys_to_virt((uint64_t *)new_phys);
            memset(new_table, 0, 4096);
            // 设置中间条目：Present, Writable, User标志继承
            *entry = new_phys | ARCH_PT_FLAG_VALID | ARCH_PT_FLAG_WRITEABLE | (flags & ARCH_PT_FLAG_USER);
        }

        uint64_t next_table_phys = *entry & ARCH_ADDR_MASK;
        current_table = phys_to_virt((uint64_t *)next_table_phys);
    }

    // 处理PTE
    uint64_t pt_index = indices[3];
    uint64_t *pte = &current_table[pt_index];
    if (*pte == 0)
    {
        *pte = (paddr & ARCH_ADDR_MASK) | flags;
    }

    // 刷新TLB
    asm volatile("invlpg (%0)" : : "r"(vaddr) : "memory");
}

// 释放虚拟地址映射并回收页表
void unmap_page(uint64_t *pml4, uint64_t vaddr)
{
    uint64_t *tables[4]; // 保存各级页表指针
    uint64_t indices[4] = {
        (vaddr >> 39) & 0x1FF,
        (vaddr >> 30) & 0x1FF,
        (vaddr >> 21) & 0x1FF,
        (vaddr >> 12) & 0x1FF};

    // 获取各级页表
    uint64_t *current = pml4;
    for (int level = 0; level < 4; ++level)
    {
        tables[level] = current;
        if (level < 3)
        {
            uint64_t entry = current[indices[level]];
            if (!(entry & ARCH_PT_FLAG_VALID))
                return; // 页表不存在
            current = (uint64_t *)phys_to_virt(entry & ARCH_ADDR_MASK);
        }
    }

    // 清除PTE并释放物理页
    uint64_t *pte = &tables[3][indices[3]];
    if (*pte & ARCH_PT_FLAG_VALID)
    {
        free_frames(*pte & ARCH_ADDR_MASK, 1);
        *pte = 0;
    }

    // 自底向上回收空闲页表
    for (int level = 3; level > 0; --level)
    {
        uint64_t *table = tables[level - 1];
        uint64_t index = indices[level - 1];
        uint64_t *entry = &table[index];

        // 检查当前页表是否全空
        bool used = false;
        uint64_t *check_table = (uint64_t *)phys_to_virt(*entry & ARCH_ADDR_MASK);
        for (int i = 0; i < 512; ++i)
        {
            if (check_table[i] & ARCH_PT_FLAG_VALID)
            {
                used = true;
                break;
            }
        }

        if (!used)
        {
            free_frames(*entry & ARCH_ADDR_MASK, 1);
            *entry = 0; // 清除上级条目
        }
        else
        {
            break; // 上层页表仍在使用，停止回收
        }
    }

    // 刷新TLB
    asm volatile("invlpg (%0)" : : "r"(vaddr) : "memory");
}

uint64_t *get_current_page_dir()
{
    uint64_t *cr3 = NULL;
    asm volatile("movq %%cr3, %0" : "=r"(cr3));
    return phys_to_virt(cr3);
}

// bool stack_range(uint64_t pml4_idx, uint64_t pdpt_idx, uint64_t pd_idx, uint64_t pt_idx, uint64_t user_stack_start, uint64_t user_stack_end)
// {
//     uint64_t addr = pml4_idx << 39 | pdpt_idx << 30 | pd_idx << 21 | pt_idx << 12;
//     return user_stack_start <= addr && addr < user_stack_end;
// }

// bool heap_range(uint64_t pml4_idx, uint64_t pdpt_idx, uint64_t pd_idx, uint64_t pt_idx, uint64_t user_heap_start, uint64_t user_heap_end)
// {
//     uint64_t addr = pml4_idx << 39 | pdpt_idx << 30 | pd_idx << 21 | pt_idx << 12;
//     return user_heap_start <= addr && addr < user_heap_end;
// }

uint64_t clone_page_table(uint64_t cr3_old, uint64_t user_stack_start, uint64_t user_stack_end)
{
    (void)user_stack_start;
    (void)user_stack_end;

    uint64_t cr3_new = alloc_frames(1); // 就不判断申请失败的情况了，不然有点麻烦，你自己加上吧
    if (cr3_new == 0)
    {
        printk("Cannot clone page table: no page can be allocated");
        return cr3_old;
    }
    // 4层嵌套for循环，简单粗暴
    // 你当然可以用算法优化一下的
    // 我就这样写了，就是给你提供个思路
    // 具体要怎么写，你自己看吧
    uint64_t *pml4_old = (uint64_t *)phys_to_virt(cr3_old & ARCH_ADDR_MASK);
    uint64_t *pml4_new = (uint64_t *)phys_to_virt(cr3_new & ARCH_ADDR_MASK);
    memset(pml4_new, 0, DEFAULT_PAGE_SIZE / 2);

    // 2048，半个页，后半个页，是内核空间，内核空间直接指针指过去就好，注意释放页表的时候不要给内核空间的页表也释放了
    memcpy(pml4_new + 256, pml4_old + 256, DEFAULT_PAGE_SIZE / 2); // 我就在代码里面假设是4k的页了，如果你认为这不妥，那就自己给这些常量换成宏定义

    for (size_t pml4_idx = 0; pml4_idx < 256; ++pml4_idx)
    { // 256 没问题，这里只复制用户空间
        uint64_t pml4e_old = pml4_old[pml4_idx];
        bool pml4e_old_valid = pml4e_old & ARCH_PT_FLAG_VALID;
        bool pml4e_old_write = pml4e_old & ARCH_PT_FLAG_WRITEABLE;
        bool pml4e_old_user = pml4e_old & ARCH_PT_FLAG_USER;

        if (!pml4e_old_valid)
            continue; // 这里给你挖上一个坑，不知道你未来会不会掉进去，^_^

        uint64_t pml4e_new = alloc_frames(1);
        pml4e_new |= ARCH_PT_FLAG_VALID;
        pml4e_new |= pml4e_old_write ? ARCH_PT_FLAG_WRITEABLE : 0;
        pml4e_new |= pml4e_old_user ? ARCH_PT_FLAG_USER : 0;
        pml4_new[pml4_idx] = pml4e_new;

        uint64_t *pdpt_old = (uint64_t *)phys_to_virt(pml4e_old & ARCH_ADDR_MASK);
        uint64_t *pdpt_new = (uint64_t *)phys_to_virt(pml4e_new & ARCH_ADDR_MASK);
        memset(pdpt_new, 0, DEFAULT_PAGE_SIZE);
        for (size_t pdpt_idx = 0; pdpt_idx < 512; ++pdpt_idx)
        {
            uint64_t pdpte_old = pdpt_old[pdpt_idx];
            bool pdpte_old_valid = pdpte_old & ARCH_PT_FLAG_VALID;
            bool pdpte_old_write = pdpte_old & ARCH_PT_FLAG_WRITEABLE;
            bool pdpte_old_user = pdpte_old & ARCH_PT_FLAG_USER;
            bool pdpte_old_large = pdpte_old & ARCH_PT_FLAG_HUGE;
            if (!pdpte_old_valid)
                continue;

            if (pdpte_old_large)
            {
                pdpt_new[pdpt_idx] = pdpte_old;
                continue;
            }

            uint64_t pdpte_new = alloc_frames(1);
            pdpte_new |= ARCH_PT_FLAG_VALID;
            pdpte_new |= pdpte_old_write ? ARCH_PT_FLAG_WRITEABLE : 0;
            pdpte_new |= pdpte_old_user ? ARCH_PT_FLAG_USER : 0;
            pdpt_new[pdpt_idx] = pdpte_new;

            uint64_t *pd_old = (uint64_t *)phys_to_virt(pdpte_old & ARCH_ADDR_MASK);
            uint64_t *pd_new = (uint64_t *)phys_to_virt(pdpte_new & ARCH_ADDR_MASK);
            memset(pd_new, 0, DEFAULT_PAGE_SIZE);
            for (size_t pd_idx = 0; pd_idx < 512; ++pd_idx)
            {
                uint64_t pde_old = pd_old[pd_idx];
                bool pde_old_valid = pde_old & ARCH_PT_FLAG_VALID;
                bool pde_old_write = pde_old & ARCH_PT_FLAG_WRITEABLE;
                bool pde_old_user = pde_old & ARCH_PT_FLAG_USER;
                bool pde_old_large = pde_old & ARCH_PT_FLAG_HUGE;
                if (!pde_old_valid)
                    continue;

                if (pde_old_large)
                {
                    pd_new[pd_idx] = pde_old;
                    continue;
                }

                uint64_t pde_new = alloc_frames(1);
                pde_new |= ARCH_PT_FLAG_VALID;
                pde_new |= pde_old_write ? ARCH_PT_FLAG_WRITEABLE : 0;
                pde_new |= pde_old_user ? ARCH_PT_FLAG_USER : 0;
                pd_new[pd_idx] = pde_new;

                uint64_t *pt_old = (uint64_t *)phys_to_virt(pde_old & ARCH_ADDR_MASK);
                uint64_t *pt_new = (uint64_t *)phys_to_virt(pde_new & ARCH_ADDR_MASK);
                memset(pt_new, 0, DEFAULT_PAGE_SIZE);
                for (size_t pt_idx = 0; pt_idx < 512; ++pt_idx)
                {
                    uint64_t pte_old = pt_old[pt_idx];
                    bool pte_old_valid = pte_old & ARCH_PT_FLAG_VALID;
                    bool pte_old_write = pte_old & ARCH_PT_FLAG_WRITEABLE;
                    bool pte_old_user = pte_old & ARCH_PT_FLAG_USER;
                    if (!pte_old_valid)
                        continue;

                    uint64_t *page_old = (uint64_t *)phys_to_virt(pte_old & ARCH_ADDR_MASK);

                    uint64_t pte_new = alloc_frames(1);
                    pte_new |= ARCH_PT_FLAG_VALID;
                    pte_new |= pte_old_write ? ARCH_PT_FLAG_WRITEABLE : 0;
                    pte_new |= pte_old_user ? ARCH_PT_FLAG_USER : 0;
                    pt_new[pt_idx] = pte_new;

                    uint64_t *page_new = (uint64_t *)phys_to_virt(pte_new & ARCH_ADDR_MASK);
                    memcpy(page_new, page_old, DEFAULT_PAGE_SIZE);
                }
            }
        }
    }
    return cr3_new;
}
